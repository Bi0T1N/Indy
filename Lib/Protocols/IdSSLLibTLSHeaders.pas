{
  This file is part of the Indy (Internet Direct) project, and is offered
  under the dual-licensing agreement described on the Indy website.
  (http://www.indyproject.org/)

  header version: $OpenBSD: tls.h,v 1.56 2019/11/02 13:37:59

  Copyright:
   (c) 1993-2005, Chad Z. Hower and the Indy Pit Crew. All rights reserved.
}
{
  Author: Bi0T1N
}
unit IdSSLLibTLSHeaders;

interface

{$I IdCompilerDefines.inc}

{$IFNDEF USE_LibreSSLTLS}
  //{$message error Should not compile if USE_LibreSSLTLS is not defined!!!}
{$ENDIF}

{$WRITEABLECONST OFF}

uses
  IdGlobal, IdCTypes;

const
  TLS_API = 20200120;
  TLS_PROTOCOL_TLSv1_0 = 1 shl 1;
  TLS_PROTOCOL_TLSv1_1 = 1 shl 2;
  TLS_PROTOCOL_TLSv1_2 = 1 shl 3;
  TLS_PROTOCOL_TLSv1_3 = 1 shl 4;
  TLS_PROTOCOL_TLSv1 = ((TLS_PROTOCOL_TLSv1_0 or TLS_PROTOCOL_TLSv1_1) or TLS_PROTOCOL_TLSv1_2) or TLS_PROTOCOL_TLSv1_3;
  TLS_PROTOCOLS_ALL = TLS_PROTOCOL_TLSv1;
  TLS_PROTOCOLS_DEFAULT = TLS_PROTOCOL_TLSv1_2 or TLS_PROTOCOL_TLSv1_3;
  TLS_WANT_POLLIN = -(2);
  TLS_WANT_POLLOUT = -(3);
  { RFC 6960 Section 2.3 }
  TLS_OCSP_RESPONSE_SUCCESSFUL = 0;
  TLS_OCSP_RESPONSE_MALFORMED = 1;
  TLS_OCSP_RESPONSE_INTERNALERROR = 2;
  TLS_OCSP_RESPONSE_TRYLATER = 3;
  TLS_OCSP_RESPONSE_SIGREQUIRED = 4;
  TLS_OCSP_RESPONSE_UNAUTHORIZED = 5;
  { RFC 6960 Section 2.2 }
  TLS_OCSP_CERT_GOOD = 0;
  TLS_OCSP_CERT_REVOKED = 1;
  TLS_OCSP_CERT_UNKNOWN = 2;
  { RFC 5280 Section 5.3.1 }
  TLS_CRL_REASON_UNSPECIFIED = 0;
  TLS_CRL_REASON_KEY_COMPROMISE = 1;
  TLS_CRL_REASON_CA_COMPROMISE = 2;
  TLS_CRL_REASON_AFFILIATION_CHANGED = 3;
  TLS_CRL_REASON_SUPERSEDED = 4;
  TLS_CRL_REASON_CESSATION_OF_OPERATION = 5;
  TLS_CRL_REASON_CERTIFICATE_HOLD = 6;
  TLS_CRL_REASON_REMOVE_FROM_CRL = 8;
  TLS_CRL_REASON_PRIVILEGE_WITHDRAWN = 9;
  TLS_CRL_REASON_AA_COMPROMISE = 10;
  TLS_MAX_SESSION_ID_LENGTH = 32;
  TLS_TICKET_KEY_SIZE = 48;

type
  PPTLS = ^PTLS;
  PTLS = ^TTLS;
  TTLS = packed record
      {undefined structure}
    end;

  PTLS_CONFIG = ^TTLS_CONFIG;
  TTLS_CONFIG = packed record
      {undefined structure}
    end;

  // callbacks
  TTLS_READ_CB = procedure(_ctx: PTLS; _buf: Pointer; _buflen: TIdC_SIZET; _cb_arg: Pointer); cdecl;
  TTLS_WRITE_CB = procedure(_ctx: PTLS; _buf: Pointer; _buflen: TIdC_SIZET; _cb_arg: Pointer); cdecl;

var
  tls_init : function: TIdC_INT cdecl = nil;
  tls_config_error : function(_config: PTLS_CONFIG): PIdAnsiChar cdecl = nil;
  tls_error : function(_ctx: PTLS): PIdAnsiChar cdecl = nil;
  tls_config_new : function: PTLS_CONFIG cdecl = nil;
  tls_config_free : procedure(_config: PTLS_CONFIG) cdecl = nil;
  tls_default_ca_cert_file : function: PIdAnsiChar cdecl = nil;
  tls_config_add_keypair_file : function(_config: PTLS_CONFIG; _cert_file: PIdAnsiChar; _key_file: PIdAnsiChar): TIdC_INT cdecl = nil;
  tls_config_add_keypair_mem : function(_config: PTLS_CONFIG; _cert: PIdC_UINT8; _cert_len: TIdC_SIZET; _key: PIdC_UINT8; _key_len: TIdC_SIZET): TIdC_INT cdecl = nil;
  tls_config_add_keypair_ocsp_file : function(_config: PTLS_CONFIG; _cert_file: PIdAnsiChar; _key_file: PIdAnsiChar; _ocsp_staple_file: PIdAnsiChar): TIdC_INT cdecl = nil;
  tls_config_add_keypair_ocsp_mem : function(_config: PTLS_CONFIG; _cert: PIdC_UINT8; _cert_len: TIdC_SIZET; _key: PIdC_UINT8; _key_len: TIdC_SIZET; _staple: PIdC_UINT8; _staple_len: TIdC_SIZET): TIdC_INT cdecl = nil;
  tls_config_set_alpn : function(_config: PTLS_CONFIG; _alpn: PIdAnsiChar): TIdC_INT cdecl = nil;
  tls_config_set_ca_file : function(_config: PTLS_CONFIG; _ca_file: PIdAnsiChar): TIdC_INT cdecl = nil;
  tls_config_set_ca_path : function(_config: PTLS_CONFIG; _ca_path: PIdAnsiChar): TIdC_INT cdecl = nil;
  tls_config_set_ca_mem : function(_config: PTLS_CONFIG; _ca: PIdC_UINT8; _len: TIdC_SIZET): TIdC_INT cdecl = nil;
  tls_config_set_cert_file : function(_config: PTLS_CONFIG; _cert_file: PIdAnsiChar): TIdC_INT cdecl = nil;
  tls_config_set_cert_mem : function(_config: PTLS_CONFIG; _cert: PIdC_UINT8; _len: TIdC_SIZET): TIdC_INT cdecl = nil;
  tls_config_set_ciphers : function(_config: PTLS_CONFIG; _ciphers: PIdAnsiChar): TIdC_INT cdecl = nil;
  tls_config_set_crl_file : function(_config: PTLS_CONFIG; _crl_file: PIdAnsiChar): TIdC_INT cdecl = nil;
  tls_config_set_crl_mem : function(_config: PTLS_CONFIG; _crl: PIdC_UINT8; _len: TIdC_SIZET): TIdC_INT cdecl = nil;
  tls_config_set_dheparams : function(_config: PTLS_CONFIG; _params: PIdAnsiChar): TIdC_INT cdecl = nil;
  tls_config_set_ecdhecurve : function(_config: PTLS_CONFIG; _curve: PIdAnsiChar): TIdC_INT cdecl = nil;
  tls_config_set_ecdhecurves : function(_config: PTLS_CONFIG; _curves: PIdAnsiChar): TIdC_INT cdecl = nil;
  tls_config_set_key_file : function(_config: PTLS_CONFIG; _key_file: PIdAnsiChar): TIdC_INT cdecl = nil;
  tls_config_set_key_mem : function(_config: PTLS_CONFIG; _key: PIdC_UINT8; _len: TIdC_SIZET): TIdC_INT cdecl = nil;
  tls_config_set_keypair_file : function(_config: PTLS_CONFIG; _cert_file: PIdAnsiChar; _key_file: PIdAnsiChar): TIdC_INT cdecl = nil;
  tls_config_set_keypair_mem : function(_config: PTLS_CONFIG; _cert: PIdC_UINT8; _cert_len: TIdC_SIZET; _key: PIdC_UINT8; _key_len: TIdC_SIZET): TIdC_INT cdecl = nil;
  tls_config_set_keypair_ocsp_file : function(_config: PTLS_CONFIG; _cert_file: PIdAnsiChar; _key_file: PIdAnsiChar; _staple_file: PIdAnsiChar): TIdC_INT cdecl = nil;
  tls_config_set_keypair_ocsp_mem : function(_config: PTLS_CONFIG; _cert: PIdC_UINT8; _cert_len: TIdC_SIZET; _key: PIdC_UINT8; _key_len: TIdC_SIZET; _staple: PIdC_UINT8; staple_len: TIdC_SIZET): TIdC_INT cdecl = nil;
  tls_config_set_ocsp_staple_mem : function(_config: PTLS_CONFIG; _staple: PIdC_UINT8; _len: TIdC_SIZET): TIdC_INT cdecl = nil;
  tls_config_set_ocsp_staple_file : function(_config: PTLS_CONFIG; _staple_file: PIdAnsiChar): TIdC_INT cdecl = nil;
  tls_config_set_protocols : function(_config: PTLS_CONFIG; _protocols: TIdC_UINT32): TIdC_INT cdecl = nil;
  tls_config_set_session_fd : function(_config: PTLS_CONFIG; _session_fd: TIdC_INT): TIdC_INT cdecl = nil;
  tls_config_set_verify_depth : function(_config: PTLS_CONFIG; _verify_depth: TIdC_INT): TIdC_INT cdecl = nil;
  tls_config_prefer_ciphers_client : procedure(_config: PTLS_CONFIG) cdecl = nil;
  tls_config_prefer_ciphers_server : procedure(_config: PTLS_CONFIG) cdecl = nil;
  tls_config_insecure_noverifycert : procedure(_config: PTLS_CONFIG) cdecl = nil;
  tls_config_insecure_noverifyname : procedure(_config: PTLS_CONFIG) cdecl = nil;
  tls_config_insecure_noverifytime : procedure(_config: PTLS_CONFIG) cdecl = nil;
  tls_config_verify : procedure(_config: PTLS_CONFIG) cdecl = nil;
  tls_config_ocsp_require_stapling : procedure(_config: PTLS_CONFIG) cdecl = nil;
  tls_config_verify_client : procedure(_config: PTLS_CONFIG) cdecl = nil;
  tls_config_verify_client_optional : procedure(_config: PTLS_CONFIG) cdecl = nil;
  tls_config_clear_keys : procedure(_config: PTLS_CONFIG) cdecl = nil;
  tls_config_parse_protocols : function(_protocols: PIdC_UINT32; _protostr: PIdAnsiChar): TIdC_INT cdecl = nil;
  tls_config_set_session_id : function(_config: PTLS_CONFIG; _session_id: PByte; _len: TIdC_SIZET): TIdC_INT cdecl = nil;
  tls_config_set_session_lifetime : function(_config: PTLS_CONFIG; _lifetime: TIdC_INT): TIdC_INT cdecl = nil;
  tls_config_add_ticket_key : function(_config: PTLS_CONFIG; _keyrev: TIdC_UINT32; _key: PByte; _keylen: TIdC_SIZET): TIdC_INT cdecl = nil;
  tls_client : function: PTLS cdecl = nil;
  tls_server : function: PTLS cdecl = nil;
  tls_configure : function(_ctx: PTLS; _config: PTLS_CONFIG): TIdC_INT cdecl = nil;
  tls_reset : procedure(_ctx: PTLS) cdecl = nil;
  tls_free : procedure(_ctx: PTLS) cdecl = nil;
  tls_accept_fds : function(_ctx: PTLS; _cctx: PPTLS; _fd_read: TIdC_INT; _fd_write: TIdC_INT): TIdC_INT cdecl = nil;
  tls_accept_socket : function(_ctx: PTLS; _cctx: PPTLS; _socket: TIdC_INT): TIdC_INT cdecl = nil;
  tls_accept_cbs : function(_ctx: PTLS; _cctx: PPTLS; _read_cb: TTLS_READ_CB; _write_cb: TTLS_WRITE_CB; _cb_arg: Pointer): TIdC_INT cdecl = nil;
  tls_connect : function(_ctx: PTLS; _host: PIdAnsiChar; _port: PIdAnsiChar): TIdC_INT cdecl = nil;
  tls_connect_fds : function(_ctx: PTLS; _fd_read: TIdC_INT; _fd_write: TIdC_INT; _servername: PIdAnsiChar): TIdC_INT cdecl = nil;
  tls_connect_servername : function(_ctx: PTLS; _host: PIdAnsiChar; _port: PIdAnsiChar; _servername: PIdAnsiChar): TIdC_INT cdecl = nil;
  tls_connect_socket : function(_ctx: PTLS; _s: TIdC_INT; _servername: PIdAnsiChar): TIdC_INT cdecl = nil;
  tls_connect_cbs : function(_ctx: PTLS; _read_cb: TTLS_READ_CB; _write_cb: TTLS_WRITE_CB; _cb_arg: Pointer; _servername: PIdAnsiChar): TIdC_INT cdecl = nil;
  tls_handshake : function(_ctx: PTLS): TIdC_INT cdecl = nil;
  tls_read : function(_ctx: PTLS; _buf: Pointer; _buflen: TIdC_SIZET): TIdC_SSIZET cdecl = nil;
  tls_write : function(_ctx: PTLS; _buf: Pointer; _buflen: TIdC_SIZET): TIdC_SSIZET cdecl = nil;
  tls_close : function(_ctx: PTLS): TIdC_INT cdecl = nil;
  tls_peer_cert_provided : function(_ctx: PTLS): TIdC_INT cdecl = nil;
  tls_peer_cert_contains_name : function(_ctx: PTLS; _name: PIdAnsiChar): TIdC_INT cdecl = nil;
  tls_peer_cert_hash : function(_ctx: PTLS): PIdAnsiChar cdecl = nil;
  tls_peer_cert_issuer : function(_ctx: PTLS): PIdAnsiChar cdecl = nil;
  tls_peer_cert_subject : function(_ctx: PTLS): PIdAnsiChar cdecl = nil;
  tls_peer_cert_notbefore : function(_ctx: PTLS): TIdC_TIMET cdecl = nil;
  tls_peer_cert_notafter : function(_ctx: PTLS): TIdC_TIMET cdecl = nil;
  tls_peer_cert_chain_pem : function(_ctx: PTLS; _len: PIdC_SSIZET): PIdC_UINT8 cdecl = nil;
  tls_conn_alpn_selected : function(_ctx: PTLS): PIdAnsiChar cdecl = nil;
  tls_conn_cipher : function(_ctx: PTLS): PIdAnsiChar cdecl = nil;
  tls_conn_cipher_strength : function(_ctx: PTLS): TIdC_INT cdecl = nil;
  tls_conn_servername : function(_ctx: PTLS): PIdAnsiChar cdecl = nil;
  tls_conn_session_resumed : function(_ctx: PTLS): TIdC_INT cdecl = nil;
  tls_conn_version : function(_ctx: PTLS): PIdAnsiChar cdecl = nil;
  tls_load_file : function(_file: PIdAnsiChar; _len: PIdC_SSIZET; _password: PIdAnsiChar): PIdC_UINT8 cdecl = nil;
  tls_unload_file : procedure(_buf: PIdC_UINT8; len: TIdC_SIZET);
  tls_ocsp_process_response : function(_ctx: PTLS; _response: PByte; _size: TIdC_SIZET): TIdC_INT cdecl = nil;
  tls_peer_ocsp_cert_status : function(_ctx: PTLS): TIdC_INT cdecl = nil;
  tls_peer_ocsp_crl_reason : function(_ctx: PTLS): TIdC_INT cdecl = nil;
  tls_peer_ocsp_next_update : function(_ctx: PTLS): TIdC_TIMET cdecl = nil;
  tls_peer_ocsp_response_status : function(_ctx: PTLS): TIdC_INT cdecl = nil;
  tls_peer_ocsp_result : function(_ctx: PTLS): PIdAnsiChar cdecl = nil;
  tls_peer_ocsp_revocation_time : function(_ctx: PTLS): TIdC_TIMET cdecl = nil;
  tls_peer_ocsp_this_update : function(_ctx: PTLS): TIdC_TIMET cdecl = nil;
  tls_peer_ocsp_url : function(_ctx: PTLS): PIdAnsiChar cdecl = nil;

function Load: Boolean;
procedure Unload;
function WhichFailedToLoad: String;
procedure IdLibTLSSetLibPath(const APath: String);
{$IFDEF UNIX}
  procedure IdLibTLSSetCanLoadSymLinks(ACanLoad: Boolean);
  procedure IdLibTLSSetLoadSymLinksFirst(ALoadFirst: Boolean);
{$ENDIF}

implementation

uses
  {$IFDEF WINDOWS}
    Windows,
  {$ENDIF}
  SysUtils, Classes
  {$IFDEF FPC}
    , DynLibs  // better add DynLibs only for fpc
  {$ENDIF};

var
  hIdLibTLS: TIdLibHandle = IdNilHandle;
  FFailedLoadList: TStringList;

  GIdLibTLSPath: String = '';
  {$IF DEFINED(UNIX)}
    GIdCanLoadSymLinks: Boolean = True;
    GIdLoadSymLinksFirst: Boolean = True;
  {$ENDIF}

const
  LibTLS_DLL_name = 'libtls';
  LibTLS_DLL_Version: array [0..5] of String = ('', '20', '19','17','15','10');

resourcestring
  RSLibTLSFailedToLoad = 'Failed to load %s.';

function LoadFunction(const FceName: String; const ACritical: Boolean = True): Pointer;
begin
  Result := {$IFDEF WINDOWS}Windows.{$ENDIF}GetProcAddress(hIdLibTLS, PChar(FceName));
  if (Result = nil) and ACritical then
  begin
    FFailedLoadList.Add(FceName);
  end;
end;

function LoadLibTLSLibrary: TIdLibHandle;
var
  i: Integer;
{$IFNDEF WINDOWS}
  {$IF DEFINED(UNIX)}
    LCanLoadSymLinks, LLoadSymLinksFirst: Boolean;
  {$ENDIF}
{$ENDIF}
begin
  {$IFDEF WINDOWS}
    //On Windows, you should use SafeLoadLibrary because
    //the LoadLibrary API call messes with the FPU control word.
    for i := Low(LibTLS_DLL_Version) to High(LibTLS_DLL_Version) do
    begin
      Result := SafeLoadLibrary(GIdLibTLSPath + LibTLS_DLL_name + '-' + LibTLS_DLL_Version[i] + '.dll');
      if Result <> IdNilHandle then
        Exit;
    end;
  {$ELSE}
    {$IF DEFINED(UNIX)}
      Result := IdNilHandle;
      LCanLoadSymLinks := GIdCanLoadSymLinks;
      LLoadSymLinksFirst := GIdLoadSymLinksFirst;

      if LCanLoadSymLinks and LLoadSymLinksFirst then
      begin
        Result := HackLoad(GIdLibTLSPath + LibTLS_DLL_name, []);
        if Result <> IdNilHandle then
        begin
          Exit;
        end;
      end;
      for i := Low(LibTLS_DLL_Version) to High(LibTLS_DLL_Version) do
      begin
        Result := HackLoad(GIdLibTLSPath + LibTLS_DLL_name, LibTLS_DLL_Version[i]);
        if Result <> IdNilHandle then
        begin
          Exit;
        end;
      end;
      if LCanLoadSymLinks and (not LLoadSymLinksFirst) then
      begin
        Result := HackLoad(GIdLibTLSPath + LibTLS_DLL_name, []);
      end;
    {$ELSE}
      Result := IdNilHandle;
    {$ENDIF}
  {$ENDIF}
end;

procedure InitializeFuncPointers;
begin
  tls_init := nil;
  tls_config_error := nil;
  tls_error := nil;
  tls_config_new := nil;
  tls_config_free := nil;
  tls_default_ca_cert_file := nil;
  tls_config_add_keypair_file := nil;
  tls_config_add_keypair_mem := nil;
  tls_config_add_keypair_ocsp_file := nil;
  tls_config_add_keypair_ocsp_mem := nil;
  tls_config_set_alpn := nil;
  tls_config_set_ca_file := nil;
  tls_config_set_ca_path := nil;
  tls_config_set_ca_mem := nil;
  tls_config_set_cert_file := nil;
  tls_config_set_cert_mem := nil;
  tls_config_set_ciphers := nil;
  tls_config_set_crl_file := nil;
  tls_config_set_crl_mem := nil;
  tls_config_set_dheparams := nil;
  tls_config_set_ecdhecurve := nil;
  tls_config_set_ecdhecurves := nil;
  tls_config_set_key_file := nil;
  tls_config_set_key_mem := nil;
  tls_config_set_keypair_file := nil;
  tls_config_set_keypair_mem := nil;
  tls_config_set_keypair_ocsp_file := nil;
  tls_config_set_keypair_ocsp_mem := nil;
  tls_config_set_ocsp_staple_mem := nil;
  tls_config_set_ocsp_staple_file := nil;
  tls_config_set_protocols := nil;
  tls_config_set_session_fd := nil;
  tls_config_set_verify_depth := nil;
  tls_config_prefer_ciphers_client := nil;
  tls_config_prefer_ciphers_server := nil;
  tls_config_insecure_noverifycert := nil;
  tls_config_insecure_noverifyname := nil;
  tls_config_insecure_noverifytime := nil;
  tls_config_verify := nil;
  tls_config_ocsp_require_stapling := nil;
  tls_config_verify_client := nil;
  tls_config_verify_client_optional := nil;
  tls_config_clear_keys := nil;
  tls_config_parse_protocols := nil;
  tls_config_set_session_id := nil;
  tls_config_set_session_lifetime := nil;
  tls_config_add_ticket_key := nil;
  tls_client := nil;
  tls_server := nil;
  tls_configure := nil;
  tls_reset := nil;
  tls_free := nil;
  tls_accept_fds := nil;
  tls_accept_socket := nil;
  tls_accept_cbs := nil;
  tls_connect := nil;
  tls_connect_fds := nil;
  tls_connect_servername := nil;
  tls_connect_socket := nil;
  tls_connect_cbs := nil;
  tls_handshake := nil;
  tls_read := nil;
  tls_write := nil;
  tls_close := nil;
  tls_peer_cert_provided := nil;
  tls_peer_cert_contains_name := nil;
  tls_peer_cert_hash := nil;
  tls_peer_cert_issuer := nil;
  tls_peer_cert_subject := nil;
  tls_peer_cert_notbefore := nil;
  tls_peer_cert_notafter := nil;
  tls_peer_cert_chain_pem := nil;
  tls_conn_alpn_selected := nil;
  tls_conn_cipher := nil;
  tls_conn_cipher_strength := nil;
  tls_conn_servername := nil;
  tls_conn_session_resumed := nil;
  tls_conn_version := nil;
  tls_load_file := nil;
  tls_unload_file := nil;
  tls_ocsp_process_response := nil;
  tls_peer_ocsp_cert_status := nil;
  tls_peer_ocsp_crl_reason := nil;
  tls_peer_ocsp_next_update := nil;
  tls_peer_ocsp_response_status := nil;
  tls_peer_ocsp_result := nil;
  tls_peer_ocsp_revocation_time := nil;
  tls_peer_ocsp_this_update := nil;
  tls_peer_ocsp_url := nil;
end;

procedure LoadFuncPointers;
begin
  @tls_init := LoadFunction('tls_init');
  @tls_config_error := LoadFunction('tls_config_error');
  @tls_error := LoadFunction('tls_error');
  @tls_config_new := LoadFunction('tls_config_new');
  @tls_config_free := LoadFunction('tls_config_free');
  @tls_default_ca_cert_file := LoadFunction('tls_default_ca_cert_file');
  @tls_config_add_keypair_file := LoadFunction('tls_config_add_keypair_file');
  @tls_config_add_keypair_mem := LoadFunction('tls_config_add_keypair_mem');
  @tls_config_add_keypair_ocsp_file := LoadFunction('tls_config_add_keypair_ocsp_file');
  @tls_config_add_keypair_ocsp_mem := LoadFunction('tls_config_add_keypair_ocsp_mem');
  @tls_config_set_alpn := LoadFunction('tls_config_set_alpn');
  @tls_config_set_ca_file := LoadFunction('tls_config_set_ca_file');
  @tls_config_set_ca_path := LoadFunction('tls_config_set_ca_path');
  @tls_config_set_ca_mem := LoadFunction('tls_config_set_ca_mem');
  @tls_config_set_cert_file := LoadFunction('tls_config_set_cert_file');
  @tls_config_set_cert_mem := LoadFunction('tls_config_set_cert_mem');
  @tls_config_set_ciphers := LoadFunction('tls_config_set_ciphers');
  @tls_config_set_crl_file := LoadFunction('tls_config_set_crl_file');
  @tls_config_set_crl_mem := LoadFunction('tls_config_set_crl_mem');
  @tls_config_set_dheparams := LoadFunction('tls_config_set_dheparams');
  @tls_config_set_ecdhecurve := LoadFunction('tls_config_set_ecdhecurve');
  @tls_config_set_ecdhecurves := LoadFunction('tls_config_set_ecdhecurves');
  @tls_config_set_key_file := LoadFunction('tls_config_set_key_file');
  @tls_config_set_key_mem := LoadFunction('tls_config_set_key_mem');
  @tls_config_set_keypair_file := LoadFunction('tls_config_set_keypair_file');
  @tls_config_set_keypair_mem := LoadFunction('tls_config_set_keypair_mem');
  @tls_config_set_keypair_ocsp_file := LoadFunction('tls_config_set_keypair_ocsp_file');
  @tls_config_set_keypair_ocsp_mem := LoadFunction('tls_config_set_keypair_ocsp_mem');
  @tls_config_set_ocsp_staple_mem := LoadFunction('tls_config_set_ocsp_staple_mem');
  @tls_config_set_ocsp_staple_file := LoadFunction('tls_config_set_ocsp_staple_file');
  @tls_config_set_protocols := LoadFunction('tls_config_set_protocols');
  @tls_config_set_session_fd := LoadFunction('tls_config_set_session_fd');
  @tls_config_set_verify_depth := LoadFunction('tls_config_set_verify_depth');
  @tls_config_prefer_ciphers_client := LoadFunction('tls_config_prefer_ciphers_client');
  @tls_config_prefer_ciphers_server := LoadFunction('tls_config_prefer_ciphers_server');
  @tls_config_insecure_noverifycert := LoadFunction('tls_config_insecure_noverifycert');
  @tls_config_insecure_noverifyname := LoadFunction('tls_config_insecure_noverifyname');
  @tls_config_insecure_noverifytime := LoadFunction('tls_config_insecure_noverifytime');
  @tls_config_verify := LoadFunction('tls_config_verify');
  @tls_config_ocsp_require_stapling := LoadFunction('tls_config_ocsp_require_stapling');
  @tls_config_verify_client := LoadFunction('tls_config_verify_client');
  @tls_config_verify_client_optional := LoadFunction('tls_config_verify_client_optional');
  @tls_config_clear_keys := LoadFunction('tls_config_clear_keys');
  @tls_config_parse_protocols := LoadFunction('tls_config_parse_protocols');
  @tls_config_set_session_id := LoadFunction('tls_config_set_session_id');
  @tls_config_set_session_lifetime := LoadFunction('tls_config_set_session_lifetime');
  @tls_config_add_ticket_key := LoadFunction('tls_config_add_ticket_key');
  @tls_client := LoadFunction('tls_client');
  @tls_server := LoadFunction('tls_server');
  @tls_configure := LoadFunction('tls_configure');
  @tls_reset := LoadFunction('tls_reset');
  @tls_free := LoadFunction('tls_free');
  @tls_accept_fds := LoadFunction('tls_accept_fds');
  @tls_accept_socket := LoadFunction('tls_accept_socket');
  @tls_accept_cbs := LoadFunction('tls_accept_cbs');
  @tls_connect := LoadFunction('tls_connect');
  @tls_connect_fds := LoadFunction('tls_connect_fds');
  @tls_connect_servername := LoadFunction('tls_connect_servername');
  @tls_connect_socket := LoadFunction('tls_connect_socket');
  @tls_connect_cbs := LoadFunction('tls_connect_cbs');
  @tls_handshake := LoadFunction('tls_handshake');
  @tls_read := LoadFunction('tls_read');
  @tls_write := LoadFunction('tls_write');
  @tls_close := LoadFunction('tls_close');
  @tls_peer_cert_provided := LoadFunction('tls_peer_cert_provided');
  @tls_peer_cert_contains_name := LoadFunction('tls_peer_cert_contains_name');
  @tls_peer_cert_hash := LoadFunction('tls_peer_cert_hash');
  @tls_peer_cert_issuer := LoadFunction('tls_peer_cert_issuer');
  @tls_peer_cert_subject := LoadFunction('tls_peer_cert_subject');
  @tls_peer_cert_notbefore := LoadFunction('tls_peer_cert_notbefore');
  @tls_peer_cert_notafter := LoadFunction('tls_peer_cert_notafter');
  @tls_peer_cert_chain_pem := LoadFunction('tls_peer_cert_chain_pem');
  @tls_conn_alpn_selected := LoadFunction('tls_conn_alpn_selected');
  @tls_conn_cipher := LoadFunction('tls_conn_cipher');
  @tls_conn_cipher_strength := LoadFunction('tls_conn_cipher_strength');
  @tls_conn_servername := LoadFunction('tls_conn_servername');
  @tls_conn_session_resumed := LoadFunction('tls_conn_session_resumed');
  @tls_conn_version := LoadFunction('tls_conn_version');
  @tls_load_file := LoadFunction('tls_load_file');
  @tls_unload_file := LoadFunction('tls_unload_file');
  @tls_ocsp_process_response := LoadFunction('tls_ocsp_process_response');
  @tls_peer_ocsp_cert_status := LoadFunction('tls_peer_ocsp_cert_status');
  @tls_peer_ocsp_crl_reason := LoadFunction('tls_peer_ocsp_crl_reason');
  @tls_peer_ocsp_next_update := LoadFunction('tls_peer_ocsp_next_update');
  @tls_peer_ocsp_response_status := LoadFunction('tls_peer_ocsp_response_status');
  @tls_peer_ocsp_result := LoadFunction('tls_peer_ocsp_result');
  @tls_peer_ocsp_revocation_time := LoadFunction('tls_peer_ocsp_revocation_time');
  @tls_peer_ocsp_this_update := LoadFunction('tls_peer_ocsp_this_update');
  @tls_peer_ocsp_url := LoadFunction('tls_peer_ocsp_url');
end;

function Load: Boolean;
begin
  Result := False;
  Assert(FFailedLoadList <> nil);

  if (hIdLibTLS <> IdNilHandle) and (FFailedLoadList.Count = 0) then
  begin
    Result := True;
    Exit;
  end;

  FFailedLoadList.Clear;

  if hIdLibTLS = IdNilHandle then
  begin
    hIdLibTLS := LoadLibTLSLibrary;
    if hIdLibTLS = IdNilHandle then
    begin
      FFailedLoadList.Add(IndyFormat(RSLibTLSFailedToLoad, [GIdLibTLSPath + LibTLS_DLL_name]));
      Exit;
    end;
  end;

  LoadFuncPointers;
end;

procedure Unload;
begin
  {$IFDEF WINDOWS}Windows.{$ENDIF}FreeLibrary(hIdLibTLS);
  hIdLibTLS := IdNilHandle;
  // reset function pointers
  InitializeFuncPointers;
end;

function WhichFailedToLoad: String;
begin
  Assert(FFailedLoadList <> nil);
  Result := FFailedLoadList.CommaText;
end;

procedure IdLibTLSSetLibPath(const APath: String);
begin
  if APath <> '' then
  begin
    GIdLibTLSPath := IndyIncludeTrailingPathDelimiter(APath);
  end
  else
  begin
    GIdLibTLSPath := '';
  end;
end;

{$IFDEF UNIX}
  procedure IdLibTLSSetCanLoadSymLinks(ACanLoad: Boolean);
  begin
    GIdCanLoadSymLinks := ACanLoad;
  end;

  procedure IdLibTLSSetLoadSymLinksFirst(ALoadFirst: Boolean);
  begin
    GIdLoadSymLinksFirst := ALoadFirst;
  end;
{$ENDIF}

initialization
  FFailedLoadList := TStringList.Create;
  InitializeFuncPointers;
finalization
  FreeAndNil(FFailedLoadList);

end.
