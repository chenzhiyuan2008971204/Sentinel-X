"""Authenticode verification via WinVerifyTrust (wintrust.dll).

Read-only: verifies a file's signature without running it. Configured with no UI, no
revocation checks and cache-only URL retrieval, so it never goes to the network.

- `verify_authenticode`: the embedded signature only.
- `verify_catalog`: the system catalog (.cat) signature. Many Windows system files have no
  embedded signature and are signed this way.
- `verify_signature`: embedded first, then catalog when there is no embedded signature.
- `inspect_signature`: the same check plus the signer certificate chain (Research Lab).

Unsigned is never treated as malicious anywhere in Sentinel X.
"""

from __future__ import annotations

import ctypes
import hashlib
import sys
import uuid
from ctypes import wintypes
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sentinelx.core.enums import SignatureStatus

WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_CHOICE_CATALOG = 2
WTD_STATEACTION_VERIFY = 1
WTD_STATEACTION_CLOSE = 2
WTD_REVOCATION_CHECK_NONE = 0x10
WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000
WINTRUST_ACTION_GENERIC_VERIFY_V2 = uuid.UUID("00AAC56B-CD44-11d0-8CC2-00C04FC295EE")
DRIVER_ACTION_VERIFY = uuid.UUID("F750E6C3-38EE-11d1-85E5-00C04FC295EE")
TRUST_E_NOSIGNATURE = 0x800B0100
CERT_NAME_SIMPLE_DISPLAY_TYPE = 4
CERT_NAME_ISSUER_FLAG = 1
MAX_CHAIN = 10

_CODES: dict[int, tuple[SignatureStatus, str]] = {
    0x00000000: (SignatureStatus.VALID, "簽章有效"),
    0x800B0100: (SignatureStatus.UNSIGNED, "檔案沒有內嵌簽章（可能為目錄檔簽章或未簽署）"),
    0x800B0003: (SignatureStatus.UNSIGNED, "此檔案格式不支援內嵌簽章"),
    0x800B0001: (SignatureStatus.UNSIGNED, "沒有適用的簽章驗證提供者"),
    0x800B0109: (SignatureStatus.UNTRUSTED_ROOT, "簽章憑證鏈結到不受信任的根憑證"),
    0x800B010A: (SignatureStatus.UNTRUSTED_ROOT, "無法建立完整的憑證鏈"),
    0x80096010: (SignatureStatus.INVALID, "簽章雜湊不符，檔案可能在簽署後被修改"),
    0x800B0111: (SignatureStatus.INVALID, "簽章憑證已被明確設為不信任"),
    0x800B0101: (SignatureStatus.INVALID, "簽章憑證已過期，且簽章沒有有效的時間戳記"),
    0x80096019: (SignatureStatus.INVALID, "簽章憑證的基本限制無效"),
    0x80092026: (SignatureStatus.UNKNOWN, "系統安全性設定不允許驗證"),
}


@dataclass(frozen=True)
class SignatureInfo:
    status: SignatureStatus
    code: int | None
    message: str
    source: str | None = None  # "EMBEDDED", "CATALOG" or None (no signature found)


@dataclass(frozen=True)
class CertInfo:
    subject: str
    issuer: str
    serial: str
    not_before: str | None
    not_after: str | None
    sha1: str
    sha256: str


@dataclass(frozen=True)
class SignatureDetail:
    """Result of `inspect_signature`. Facts about the signature, never a verdict."""

    status: SignatureStatus
    code: int | None
    message: str
    source: str | None = None
    catalog_file: str | None = None
    chain: tuple[CertInfo, ...] = ()  # signer first, root last
    timestamped: bool = False
    signing_time: str | None = None  # from the timestamp countersignature, when present
    notes: tuple[str, ...] = field(default=())

    def info(self) -> SignatureInfo:
        return SignatureInfo(self.status, self.code, self.message, self.source)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value, "code": f"0x{self.code:08X}" if self.code is not None else None,
            "message": self.message, "source": self.source, "catalog_file": self.catalog_file,
            "timestamped": self.timestamped, "signing_time": self.signing_time, "notes": list(self.notes),
            "chain": [c.__dict__.copy() for c in self.chain],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SignatureDetail:
        code = d.get("code")
        return cls(SignatureStatus(d["status"]), int(code, 16) if code else None, d.get("message", ""),
                   d.get("source"), d.get("catalog_file"), tuple(CertInfo(**c) for c in d.get("chain", [])),
                   bool(d.get("timestamped")), d.get("signing_time"), tuple(d.get("notes", [])))


class _GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_ubyte * 8)]

    @classmethod
    def from_uuid(cls, u: uuid.UUID) -> _GUID:
        b = u.bytes_le
        g = cls()
        ctypes.memmove(ctypes.addressof(g), b, 16)
        return g


class _WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR),
                ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.c_void_p)]


class _WINTRUST_CATALOG_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("dwCatalogVersion", wintypes.DWORD),
                ("pcwszCatalogFilePath", wintypes.LPCWSTR), ("pcwszMemberTag", wintypes.LPCWSTR),
                ("pcwszMemberFilePath", wintypes.LPCWSTR), ("hMemberFile", wintypes.HANDLE),
                ("pbCalculatedFileHash", ctypes.c_void_p), ("cbCalculatedFileHash", wintypes.DWORD),
                ("pcCatalogContext", ctypes.c_void_p), ("hCatAdmin", wintypes.HANDLE)]


class _WINTRUST_DATA(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
                ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                ("pUnion", ctypes.c_void_p), ("dwStateAction", wintypes.DWORD),
                ("hWVTStateData", wintypes.HANDLE), ("pwszURLReference", wintypes.LPCWSTR),
                ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD),
                ("pSignatureSettings", ctypes.c_void_p)]


class _CATALOG_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("wszCatalogFile", ctypes.c_wchar * 260)]


class _FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]


class _CRYPT_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


class _CRYPT_ALGORITHM_IDENTIFIER(ctypes.Structure):
    _fields_ = [("pszObjId", ctypes.c_char_p), ("Parameters", _CRYPT_BLOB)]


class _CERT_INFO(ctypes.Structure):  # leading fields only; we never allocate it
    _fields_ = [("dwVersion", wintypes.DWORD), ("SerialNumber", _CRYPT_BLOB),
                ("SignatureAlgorithm", _CRYPT_ALGORITHM_IDENTIFIER), ("Issuer", _CRYPT_BLOB),
                ("NotBefore", _FILETIME), ("NotAfter", _FILETIME), ("Subject", _CRYPT_BLOB)]


class _CERT_CONTEXT(ctypes.Structure):
    _fields_ = [("dwCertEncodingType", wintypes.DWORD), ("pbCertEncoded", ctypes.POINTER(ctypes.c_ubyte)),
                ("cbCertEncoded", wintypes.DWORD), ("pCertInfo", ctypes.POINTER(_CERT_INFO)),
                ("hCertStore", ctypes.c_void_p)]


class _CRYPT_PROVIDER_CERT(ctypes.Structure):  # leading fields only
    _fields_ = [("cbStruct", wintypes.DWORD), ("pCert", ctypes.POINTER(_CERT_CONTEXT))]


class _CRYPT_PROVIDER_SGNR(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("sftVerifyAsOf", _FILETIME), ("csCertChain", wintypes.DWORD),
                ("pasCertChain", ctypes.c_void_p), ("dwSignerType", wintypes.DWORD), ("psSigner", ctypes.c_void_p),
                ("dwError", wintypes.DWORD), ("csCounterSigners", wintypes.DWORD),
                ("pasCounterSigners", ctypes.c_void_p), ("pChainContext", ctypes.c_void_p)]


_EPOCH_1601 = datetime(1601, 1, 1, tzinfo=UTC)


def _filetime_iso(ft: _FILETIME) -> str | None:
    v = (ft.dwHighDateTime << 32) | ft.dwLowDateTime
    if v == 0:
        return None
    try:
        return (_EPOCH_1601 + timedelta(microseconds=v // 10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except OverflowError:
        return None


class _Api:
    """Typed wintrust/crypt32 entry points, loaded once."""

    _inst: _Api | None = None

    def __init__(self) -> None:
        w = ctypes.WinDLL("wintrust.dll")
        c = ctypes.WinDLL("crypt32.dll")
        H, D, B, P = wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL, ctypes.c_void_p

        def f(lib: Any, name: str, args: list[Any], res: Any) -> Any:
            fn = getattr(lib, name)
            fn.argtypes, fn.restype = args, res
            return fn

        self.verify = f(w, "WinVerifyTrust", [wintypes.HWND, ctypes.POINTER(_GUID), P], ctypes.c_long)
        self.prov_data = f(w, "WTHelperProvDataFromStateData", [H], P)
        self.prov_signer = f(w, "WTHelperGetProvSignerFromChain", [P, D, B, D], ctypes.POINTER(_CRYPT_PROVIDER_SGNR))
        self.prov_cert = f(w, "WTHelperGetProvCertFromChain", [ctypes.POINTER(_CRYPT_PROVIDER_SGNR), D],
                           ctypes.POINTER(_CRYPT_PROVIDER_CERT))
        self.cat_acquire2 = f(w, "CryptCATAdminAcquireContext2", [ctypes.POINTER(H), ctypes.POINTER(_GUID),
                                                                   wintypes.LPCWSTR, P, D], B)
        self.cat_hash2 = f(w, "CryptCATAdminCalcHashFromFileHandle2", [H, H, ctypes.POINTER(D), P, D], B)
        self.cat_enum = f(w, "CryptCATAdminEnumCatalogFromHash", [H, P, D, D, ctypes.POINTER(H)], H)
        self.cat_info = f(w, "CryptCATCatalogInfoFromContext", [H, ctypes.POINTER(_CATALOG_INFO), D], B)
        self.cat_release_cat = f(w, "CryptCATAdminReleaseCatalogContext", [H, H, D], B)
        self.cat_release = f(w, "CryptCATAdminReleaseContext", [H, D], B)
        self.name = f(c, "CertGetNameStringW", [ctypes.POINTER(_CERT_CONTEXT), D, D, P, wintypes.LPWSTR, D], D)

    @classmethod
    def get(cls) -> _Api:
        if cls._inst is None:
            cls._inst = cls()
        return cls._inst


def _cert_name(api: _Api, cert: Any, flags: int) -> str:
    n = api.name(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, None, None, 0)
    if n <= 1:
        return ""
    buf = ctypes.create_unicode_buffer(n)
    api.name(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, None, buf, n)
    return buf.value


def _cert_info(api: _Api, cert_ptr: Any) -> CertInfo:
    ctx = cert_ptr.contents
    der = ctypes.string_at(ctx.pbCertEncoded, ctx.cbCertEncoded)
    ci = ctx.pCertInfo.contents
    serial = ctypes.string_at(ci.SerialNumber.pbData, ci.SerialNumber.cbData)[::-1].hex().upper()  # stored little-endian
    return CertInfo(
        subject=_cert_name(api, cert_ptr, 0), issuer=_cert_name(api, cert_ptr, CERT_NAME_ISSUER_FLAG),
        serial=serial, not_before=_filetime_iso(ci.NotBefore), not_after=_filetime_iso(ci.NotAfter),
        sha1=hashlib.sha1(der).hexdigest().upper(), sha256=hashlib.sha256(der).hexdigest().upper(),
    )


@dataclass
class _Outcome:
    rc: int
    chain: list[CertInfo] = field(default_factory=list)
    timestamped: bool = False
    signing_time: str | None = None
    notes: list[str] = field(default_factory=list)


def _win_verify(api: _Api, choice: int, union: ctypes.Structure, details: bool) -> _Outcome:
    data = _WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(_WINTRUST_DATA)
    data.dwUIChoice = WTD_UI_NONE
    data.fdwRevocationChecks = WTD_REVOKE_NONE
    data.dwUnionChoice = choice
    data.pUnion = ctypes.cast(ctypes.pointer(union), ctypes.c_void_p)
    data.dwStateAction = WTD_STATEACTION_VERIFY
    data.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL
    action = _GUID.from_uuid(WINTRUST_ACTION_GENERIC_VERIFY_V2)
    no_ui = wintypes.HWND(-1)  # INVALID_HANDLE_VALUE: never show UI
    out = _Outcome(api.verify(no_ui, ctypes.byref(action), ctypes.byref(data)) & 0xFFFFFFFF)
    try:
        if details and data.hWVTStateData:
            _read_chain(api, data.hWVTStateData, out)
    except OSError as exc:  # ctypes turns access violations into OSError; details are optional
        out.notes.append(f"無法讀取憑證鏈：{exc}")
    finally:
        data.dwStateAction = WTD_STATEACTION_CLOSE
        api.verify(no_ui, ctypes.byref(action), ctypes.byref(data))
    return out


def _read_chain(api: _Api, state: int, out: _Outcome) -> None:
    prov = api.prov_data(state)
    if not prov:
        return
    sgnr = api.prov_signer(prov, 0, False, 0)
    if not sgnr:
        return
    s = sgnr.contents
    for i in range(min(s.csCertChain, MAX_CHAIN)):
        pc = api.prov_cert(sgnr, i)
        if pc and pc.contents.pCert:
            out.chain.append(_cert_info(api, pc.contents.pCert))
    out.timestamped = s.csCounterSigners > 0
    if out.timestamped:
        out.signing_time = _filetime_iso(s.sftVerifyAsOf)


def _embedded(api: _Api, path: Path, details: bool) -> _Outcome:
    fi = _WINTRUST_FILE_INFO(ctypes.sizeof(_WINTRUST_FILE_INFO), str(path), None, None)
    return _win_verify(api, WTD_CHOICE_FILE, fi, details)


def _catalog(api: _Api, path: Path, details: bool) -> tuple[_Outcome, str] | None:
    """Verify against the system catalog. None when no catalog contains the file's hash."""
    import msvcrt

    with open(path, "rb") as fh:
        handle = msvcrt.get_osfhandle(fh.fileno())
        for alg in ("SHA256", "SHA1"):
            admin = wintypes.HANDLE()
            subsystem = _GUID.from_uuid(DRIVER_ACTION_VERIFY)
            if not api.cat_acquire2(ctypes.byref(admin), ctypes.byref(subsystem), alg, None, 0):
                continue
            try:
                size = wintypes.DWORD(64)
                buf = (ctypes.c_ubyte * 64)()
                if not api.cat_hash2(admin, handle, ctypes.byref(size), buf, 0):
                    continue
                cat = api.cat_enum(admin, buf, size, 0, None)
                if not cat:
                    continue
                try:
                    ci = _CATALOG_INFO()
                    ci.cbStruct = ctypes.sizeof(_CATALOG_INFO)
                    if not api.cat_info(cat, ctypes.byref(ci), 0):
                        continue
                    tag = bytes(buf[: size.value]).hex().upper()
                    info = _WINTRUST_CATALOG_INFO()
                    info.cbStruct = ctypes.sizeof(_WINTRUST_CATALOG_INFO)
                    info.pcwszCatalogFilePath = ci.wszCatalogFile
                    info.pcwszMemberTag = tag
                    info.pcwszMemberFilePath = str(path)
                    info.hMemberFile = handle
                    info.pbCalculatedFileHash = ctypes.cast(buf, ctypes.c_void_p)
                    info.cbCalculatedFileHash = size.value
                    info.hCatAdmin = admin
                    return _win_verify(api, WTD_CHOICE_CATALOG, info, details), ci.wszCatalogFile
                finally:
                    api.cat_release_cat(admin, cat, 0)
            finally:
                api.cat_release(admin, 0)
    return None


def _status(rc: int) -> tuple[SignatureStatus, str]:
    return _CODES.get(rc, (SignatureStatus.UNKNOWN, f"未知的驗證結果 0x{rc:08X}"))


def _run(path: Path, *, catalog: bool, details: bool) -> SignatureDetail:
    if sys.platform != "win32":
        return SignatureDetail(SignatureStatus.UNKNOWN, None, "僅支援 Windows")
    try:
        api = _Api.get()
        emb = _embedded(api, path, details)
        st, msg = _status(emb.rc)
        if st is not SignatureStatus.UNSIGNED or not catalog:
            source = None if st is SignatureStatus.UNSIGNED else "EMBEDDED"
            return SignatureDetail(st, emb.rc, msg, source, None, tuple(emb.chain), emb.timestamped,
                                   emb.signing_time, tuple(emb.notes))
        found = _catalog(api, path, details)
    except OSError as exc:
        return SignatureDetail(SignatureStatus.UNKNOWN, None, f"無法呼叫 WinVerifyTrust：{exc}")
    if found is None:
        return SignatureDetail(SignatureStatus.UNSIGNED, emb.rc, f"{msg}；系統目錄檔中也找不到", None)
    out, cat_file = found
    st, msg = _status(out.rc)
    if st is SignatureStatus.VALID:
        msg = "目錄檔簽章有效"
    return SignatureDetail(st, out.rc, msg, "CATALOG", cat_file, tuple(out.chain), out.timestamped,
                           out.signing_time, tuple(out.notes))


def verify_authenticode(path: Path) -> SignatureInfo:
    """Embedded signature only."""
    return _run(path, catalog=False, details=False).info()


def verify_signature(path: Path) -> SignatureInfo:
    """Embedded signature, then the system catalog when the file has no embedded signature."""
    return _run(path, catalog=True, details=False).info()


def inspect_signature(path: Path) -> SignatureDetail:
    """Like `verify_signature`, plus the signer certificate chain and timestamp."""
    return _run(path, catalog=True, details=True)


