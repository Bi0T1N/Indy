{
  $Project$
  $Workfile$
  $Revision$
  $DateUTC$
  $Id$

  This file is part of the Indy (Internet Direct) project, and is offered
  under the dual-licensing agreement described on the Indy website.
  (http://www.indyproject.org/)

  Copyright:
   (c) 1993-2005, Chad Z. Hower and the Indy Pit Crew. All rights reserved.
}
{
  Author: Bi0T1N
}
unit IdSSLLibTLS;

interface

{$i IdCompilerDefines.inc}

uses
  {$IFDEF WINDOWS}
    Windows,
  {$ENDIF}
  Classes,
  IdGlobal,
  IdException,
  IdSSL,
  IdSSLLibTLSHeaders,
  IdCustomTransparentProxy,
  IdURI,
  IdCTypes;

// TODO: put into IdSSL.pas (see github MR)
type
  TIdTLSVersion = (tlsvTLS_flexible, tlsvTLSv1_0, tlsvTLSv1_1, tlsvTLSv1_2, tlsvTLSv1_3);
  TIdTLSVersions = set of TIdTLSVersion;

  EIdLibTLSError = class(EIdException); // general failures
  EIdLibTLSConfigError = class(EIdException); // config setting failures
  EIdLibTLSOCSPError = class(EIdException); // OCSP stapling failures

type
  TIdX509 = class(TObject)
  protected
    FProvided: Boolean;
    FCertSHA256: String;
    FCertificateAsPEM: array of TIdC_UINT8;
    FIssuer: String;
    FSubject: String;
    FNotBefore: TDateTime;
    FNotAfter: TDateTime;

    function GetCertificateAsPEM: String;
  public
    constructor Create;
    procedure UpdateCertificateInfo(const ATLS_CLIENT: PTLS);

    property CertificateProvided: Boolean read FProvided;
    property CertAsSHA256: String read FCertSHA256;
    property CertificateAsPEM: String read GetCertificateAsPEM;
    property Issuer: String read FIssuer;
    property Subject: String read FSubject;
    property notBefore: TDateTime read FNotBefore;
    property notAfter: TDateTime read FNotAfter;
  end;

  TIdOCSPStapling = class(TObject)
  protected
    FCertStaus: TIdC_INT; { RFC 6960 Section 2.2 }
    FRevocationReason: TIdC_INT; { RFC 5280 Section 5.3.1 }
    FResponseStatus: TIdC_INT; { RFC 6960 Section 2.3 }
    FResultAsString: String;
    FURL: String;
    FNextUpdateTime: TDateTime;
    FRevocationTime: TDateTime;
    FThisUpdateTime: TDateTime;

  public
    constructor Create;
    procedure UpdateOCSPStaplingInfo(const ATLS_CLIENT: PTLS);

    property CertStaus: TIdC_INT read FCertStaus;
    property RevocationReason: TIdC_INT read FRevocationReason;
    property ResponseStatus: TIdC_INT read FResponseStatus;
    property ResultAsString: String read FResultAsString;
    property URL: String read FURL;
    property NextUpdateTime: TDateTime read FNextUpdateTime;
    property RevocationTime: TDateTime read FRevocationTime;
    property ThisUpdateTime: TDateTime read FThisUpdateTime;
  end;

  // TODO
  // maybe add TIdTLSOptions where all options are saved in

  TIdTLSConfig = class(TObject)
  private
    FTLS_CONFIG: PTLS_CONFIG;
    FTLSProtocolMethod: TIdC_UINT32; // value for TLS_PROTOCOL*
    FTLSVersions: TIdTLSVersions;
    FRootCertPath: String;
    FUseOCSPStapling: Boolean;

    procedure SetTLSVersions(const AValue: TIdTLSVersions);
  public
    constructor Create;
    destructor Destroy; override;
    procedure Init;

    property TLS_CONFIG: PTLS_CONFIG read FTLS_CONFIG;
    property TLSVersions: TIdTLSVersions read FTLSVersions write SetTLSVersions default [tlsvTLS_flexible];
    property RootCertPath: String read FRootCertPath write FRootCertPath;
    property UseOCSPStapling: Boolean read FUseOCSPStapling write FUseOCSPStapling;
  end;

  TPeerCertificateEvent = procedure(const ACertificate: TIdX509) of object;
  TVerifyOCSPStaplingEvent = function(const AOCSPStaplingResponse: TIdOCSPStapling): Boolean of object;

  TIdSSLIOHandlerSocketLibTLS = class(TIdSSLIOHandlerSocketBase)
  private
    FTLS_CLIENT: PTLS;
    FTLSConfig: TIdTLSConfig;
    FX509: TIdX509;
    FOnPeerCertificate: TPeerCertificateEvent;
    FOCSPStapling: TIdOCSPStapling;
    FOnVerifyOCSPStapling: TVerifyOCSPStaplingEvent;

    function GetTargetHost: String;
    procedure OpenSecureConnection;
  protected
    function RecvEnc(var ABuffer: TIdBytes): Integer; override;
    function SendEnc(const ABuffer: TIdBytes; const AOffset, ALength: Integer): Integer; override;
    procedure ConnectClient; override;
    function CheckForError(ALastResult: Integer): Integer; override;
    procedure RaiseError(AError: Integer); override;
    procedure SetPassThrough(const AValue: Boolean); override;
    procedure InitComponent; override;

    procedure PeerCertificateCallback;
    procedure DoPeerCertificate(const ACertificate: TIdX509);

    function VerifyOCSPCallback: Boolean;
    function DoVerifyOCSP(const AOCSPStaplingResponse: TIdOCSPStapling): Boolean;
  public
    destructor Destroy; override;
    procedure Close; override;
    function Clone: TIdSSLIOHandlerSocketBase; override;
    procedure StartSSL; override;

    property TLSContext: TIdTLSConfig read FTLSConfig write FTLSConfig;
    property X509: TIdX509 read FX509;
  published
    property OnPeerCertificate: TPeerCertificateEvent read FOnPeerCertificate write FOnPeerCertificate;
    property OnVerifyOCSPStapling: TVerifyOCSPStaplingEvent read FOnVerifyOCSPStapling write FOnVerifyOCSPStapling;
  end;

  TIdServerIOHandlerLibTLS = class(TIdServerIOHandlerSSLBase)
  private
  {
    TODO
  }
  end;

var
  LogFile: TextFile;

procedure Log(const AText: String);

implementation

uses
  SysUtils, DateUtils, IdStackConsts;

const
  INTERNAL_ERROR_CODE = -111;

procedure Log(const AText: String);
begin
  Append(LogFile);
  writeln(LogFile, TimeToStr(Now) + ' ' + AText); 
  CloseFile(LogFile);
end;

{ TIdX509 }

constructor TIdX509.Create;
begin
  inherited Create;

  FProvided := False;
  FCertSHA256 := '';
  SetLength(FCertificateAsPEM, 0);
  FIssuer := '';
  FSubject := '';
  FNotBefore := UnixToDateTime(0);
  FNotAfter := UnixToDateTime(0);
end;

procedure TIdX509.UpdateCertificateInfo(const ATLS_CLIENT: PTLS);
var
  lSize: TIdC_SSIZET;
  lCertChain: PIdC_UINT8;
  i: Integer;
  lTime: TIdC_TIMET;
begin
  FProvided := Boolean(tls_peer_cert_provided(ATLS_CLIENT));
  FCertSHA256 := tls_peer_cert_hash(ATLS_CLIENT);
  {$IFNDEF MSWINDOWS}
    // not available in old Windows LibTLS version
    lCertChain := tls_peer_cert_chain_pem(ATLS_CLIENT, @lSize);
    Log('Return length of tls_peer_cert_chain_pem: '+IntToStr(lSize));
    SetLength(FCertificateAsPEM, lSize);
    for i := 0 to lSize - 1 do
      FCertificateAsPEM[i] := lCertChain[i];
  {$ENDIF}
  FIssuer := tls_peer_cert_issuer(ATLS_CLIENT);
  FSubject := tls_peer_cert_subject(ATLS_CLIENT);
  lTime := tls_peer_cert_notbefore(ATLS_CLIENT);
  FNotBefore := UnixToDateTime(lTime);
  lTime := tls_peer_cert_notafter(ATLS_CLIENT);
  FNotAfter := UnixToDateTime(lTime);
end;

function TIdX509.GetCertificateAsPEM: String;
var
  lLength: Integer;
  i: Integer;
begin
  // TODO
  Result := '';
  lLength := Length(FCertificateAsPEM);
  for i := 0 to lLength - 1 do
    Result := Result + IntToStr(FCertificateAsPEM[i]);

  Result := TEncoding.ANSI.GetString(TBytes(FCertificateAsPEM), 0, lLength); // that works
end;

{ TIdOCSPStapling }

constructor TIdOCSPStapling.Create;
begin
  inherited Create;

  FCertStaus := 0;
  FRevocationReason := 0;
  FResponseStatus := 0;
  FResultAsString := '';
  FURL := '';
  FNextUpdateTime := UnixToDateTime(0);
  FRevocationTime := UnixToDateTime(0);
  FThisUpdateTime := UnixToDateTime(0);
end;

procedure TIdOCSPStapling.UpdateOCSPStaplingInfo(const ATLS_CLIENT: PTLS);
var
  lTime: TIdC_TIMET;
begin
  FCertStaus := tls_peer_ocsp_cert_status(ATLS_CLIENT);
  Log(tls_error(ATLS_CLIENT));
  FRevocationReason := tls_peer_ocsp_crl_reason(ATLS_CLIENT);
  Log(tls_error(ATLS_CLIENT));
  FResponseStatus := tls_peer_ocsp_response_status(ATLS_CLIENT);
  Log(tls_error(ATLS_CLIENT));
  FResultAsString := tls_peer_ocsp_result(ATLS_CLIENT);
  Log(tls_error(ATLS_CLIENT));
  FURL := tls_peer_ocsp_url(ATLS_CLIENT);
  Log(tls_error(ATLS_CLIENT));
  lTime := tls_peer_ocsp_next_update(ATLS_CLIENT);
  Log(tls_error(ATLS_CLIENT));
  FNextUpdateTime := UnixToDateTime(lTime);
  lTime := tls_peer_ocsp_revocation_time(ATLS_CLIENT);
  Log(tls_error(ATLS_CLIENT));
  FRevocationTime := UnixToDateTime(lTime);
  lTime := tls_peer_ocsp_this_update(ATLS_CLIENT);
  Log(tls_error(ATLS_CLIENT));
  FThisUpdateTime := UnixToDateTime(lTime);
end;

{ TIdTLSConfig }

constructor TIdTLSConfig.Create;
begin
  inherited Create;

  FTLS_CONFIG := tls_config_new();
  if (FTLS_CONFIG = nil) then
  begin
    Log('tls_config_new failed!');
    raise EIdLibTLSError.Create('tls_config_new failed!');
  end;

  FTLSProtocolMethod := TLS_PROTOCOLS_DEFAULT;
  FUseOCSPStapling := False; // doesn't work atm
end;

destructor TIdTLSConfig.Destroy;
begin
  if FTLS_CONFIG <> nil then
  begin
    tls_config_free(FTLS_CONFIG);
    FTLS_CONFIG := nil;
  end;

  inherited Destroy;
end;

procedure TIdTLSConfig.Init;
var
  rc: Integer;
begin
  rc := tls_config_set_protocols(FTLS_CONFIG, FTLSProtocolMethod);
  if (rc <> 0) then
  begin
    Log(tls_config_error(FTLS_CONFIG));
    raise EIdLibTLSConfigError.Create(tls_config_error(FTLS_CONFIG));
  end;

  {$IFDEF MSWINDOWS}
    // TODO
    // INSECURE!! //
    // but avoids
    // Exception: failed to open CA file 'c:/libressl/ssl/cert.pem': No such file or directory
    // as not available via downloaded old LibreSSL version
    tls_config_insecure_noverifycert(FTLS_CONFIG);
  {$ENDIF}

  {$IF DEFINED(LINUX)}
    // Exception: failed to open CA file '/etc/ssl/cert.pem': No such file or directory
    // for linux it's in /etc/ssl/certs/ instead of /etc/ssl/
    rc := tls_config_set_ca_path(FTLS_CONFIG, '/etc/ssl/certs/');
    if (rc <> 0) then
    begin
      Log(tls_config_error(FTLS_CONFIG));
      raise EIdLibTLSConfigError.Create(tls_config_error(FTLS_CONFIG));
    end;

{
  no idea if this is right/needed
    rc := tls_config_set_ocsp_staple_file(FTLS_CONFIG, '/etc/ssl/certs/ca-certificates.crt');
    if (rc <> 0) then
    begin
      Log(tls_config_error(FTLS_CONFIG));
      raise EIdLibTLSConfigError.Create(tls_config_error(FTLS_CONFIG));
    end;
}
  {$ENDIF}
  {$IFNDEF MSWINDOWS}
    // function not available in old windows library
    FRootCertPath := tls_default_ca_cert_file();
    Log('Root certificate path: '+FRootCertPath);
  {$ENDIF}

  if FUseOCSPStapling then
    tls_config_ocsp_require_stapling(FTLS_CONFIG);
end;

procedure TIdTLSConfig.SetTLSVersions(const AValue: TIdTLSVersions);
begin
  FTLSVersions := AValue;

  if FTLSVersions = [tlsvTLSv1_0] then
  begin
    FTLSProtocolMethod := TLS_PROTOCOL_TLSv1_0;
  end
  else if FTLSVersions = [tlsvTLSv1_1] then
  begin
    FTLSProtocolMethod := TLS_PROTOCOL_TLSv1_1;
  end
  else if FTLSVersions = [tlsvTLSv1_2] then
  begin
    FTLSProtocolMethod := TLS_PROTOCOL_TLSv1_2;
  end
  else if FTLSVersions = [tlsvTLSv1_3] then
  begin
    FTLSProtocolMethod := TLS_PROTOCOL_TLSv1_3;
  end
  else
  begin
    FTLSProtocolMethod := TLS_PROTOCOLS_ALL;
    if (tlsvTLS_flexible in FTLSVersions) then
    begin
      Exclude(FTLSVersions, tlsvTLS_flexible);
      if FTLSVersions = [] then
      begin
        FTLSVersions := [tlsvTLSv1_0, tlsvTLSv1_1, tlsvTLSv1_2, tlsvTLSv1_3];
      end;
    end;
  end;
end;

{ TIdSSLIOHandlerSocketLibTLS }

function TIdSSLIOHandlerSocketLibTLS.GetTargetHost: String;
var
  LURI: TIdURI;
  LTransparentProxy, LNextTransparentProxy: TIdCustomTransparentProxy;
begin
  Result := '';

  if URIToCheck <> '' then
  begin
    LURI := TIdURI.Create(URIToCheck);
    try
      Result := LURI.Host;
    finally
      LURI.Free;
    end;
    if Result <> '' then
      Exit;
  end;

  LTransparentProxy := FTransparentProxy;
  if Assigned(LTransparentProxy) then
  begin
    if LTransparentProxy.Enabled then
    begin
      repeat
        LNextTransparentProxy := LTransparentProxy.ChainedProxy;
        if not Assigned(LNextTransparentProxy) then Break;
        if not LNextTransparentProxy.Enabled then Break;
        LTransparentProxy := LNextTransparentProxy;
      until False;
      Result := LTransparentProxy.Host;
      if Result <> '' then
        Exit;
    end;
  end;

  Result := Host;
end;

procedure TIdSSLIOHandlerSocketLibTLS.OpenSecureConnection;
var
  rc: Integer;
  LHost: String;
  ret: Integer;
begin
  Log('- OpenSecureConnection -');

  FTLS_CLIENT := tls_client();
  if (FTLS_CLIENT = nil) then
  begin
    Log('tls_client failed!');
    raise EIdLibTLSError.Create('tls_client failed!');
  end;

  // sets config values
  FTLSConfig.Init;

  rc := tls_configure(FTLS_CLIENT, FTLSConfig.TLS_CONFIG);
  if (rc <> 0) then
  begin
    Log(tls_error(FTLS_CLIENT));
    raise EIdLibTLSError.Create(tls_error(FTLS_CLIENT));
  end;

  if IsPeer then
  begin
    // act as server
    rc := tls_accept_socket(FTLS_CLIENT, Pointer(FTLS_CLIENT), Binding.Handle);
  end
  else
  begin
    // act as client
    LHost := GetTargetHost;
    rc := tls_connect_socket(FTLS_CLIENT, Binding.Handle, @LHost[1]);
  end;
  if (rc <> 0) then
  begin
    Log(tls_error(FTLS_CLIENT));
    raise EIdLibTLSError.Create(tls_error(FTLS_CLIENT));
  end;

  // do explicit handshake to verify certificate before sending data
  repeat
    ret := tls_handshake(FTLS_CLIENT);

    if ((ret = TLS_WANT_POLLIN) or (ret = TLS_WANT_POLLOUT)) then
    begin
      Log('continue due to '+IntToStr(ret));
      Continue;
    end;

    if (ret < 0) then
    begin
      Log(tls_error(FTLS_CLIENT));
      raise EIdLibTLSError.Create(tls_error(FTLS_CLIENT));
    end;

    Break;
  until False;

  FX509.UpdateCertificateInfo(FTLS_CLIENT);
  PeerCertificateCallback;

  if FTLSConfig.UseOCSPStapling then
  begin
    FOCSPStapling.UpdateOCSPStaplingInfo(FTLS_CLIENT);
    Log('cfg err: ' + tls_config_error(FTLSConfig.TLS_CONFIG));
    Log('err: ' + tls_error(FTLS_CLIENT));
    Log(IntToStr(FOCSPStapling.FCertStaus));
    Log(IntToStr(FOCSPStapling.FRevocationReason));
    Log(IntToStr(FOCSPStapling.FResponseStatus));
    Log(FOCSPStapling.ResultAsString);

    if not VerifyOCSPCallback then
      raise EIdLibTLSOCSPError.Create(Format('Invalid OCSP Stapling result! err: %s - reason: %s', [tls_error(FTLS_CLIENT), FOCSPStapling.ResultAsString]));
  end;
end;

function TIdSSLIOHandlerSocketLibTLS.RecvEnc(var ABuffer: TIdBytes): Integer;
var
  ret: Integer;
begin
  Log('- RecvEnc -');

  repeat
    ret := tls_read(FTLS_CLIENT, PByte(ABuffer), Length(ABuffer));

    Log('bytes read: '+IntToStr(ret)+' buffer length '+IntToStr(Length(ABuffer)));
    Log(TEncoding.ANSI.GetString(TBytes(ABuffer), 0, Result));

    if ((ret = TLS_WANT_POLLIN) or (ret = TLS_WANT_POLLOUT)) then
    begin
      Log('continue due to '+IntToStr(ret));
      Continue;
    end;

    if (ret < 0) then
    begin
      Result := INTERNAL_ERROR_CODE;
      Exit;
    end;

    if (ret > 0) then
    begin
      Log('bigger than zero');
      Result := ret;
    end
    else
    begin
      Log('zero bytes read');
      Result := 0;
    end;
    Exit;
  until False;
end;

function TIdSSLIOHandlerSocketLibTLS.SendEnc(const ABuffer: TIdBytes; const AOffset, ALength: Integer): Integer;
var
  LBytesLeftToWrite, LBytesWritten, LOffset: Integer;
begin
  Log('- SendEnc -');
  Log(TEncoding.ANSI.GetString(TBytes(ABuffer), AOffset, ALength));

  LOffset := AOffset;
  LBytesLeftToWrite := ALength;
  Log('offset: '+IntToStr(LOffset));
  Log('bytes to write: '+IntToStr(LBytesLeftToWrite));
  while (LBytesLeftToWrite > 0) do
  begin
    LBytesWritten := tls_write(FTLS_CLIENT, @ABuffer[LOffset], LBytesLeftToWrite);
    Log('written bytes: '+IntToStr(LBytesWritten));
    if ((LBytesWritten = TLS_WANT_POLLIN) or (LBytesWritten = TLS_WANT_POLLOUT)) then
    begin
      Continue;
    end;

    if (LBytesWritten < 0) then
    begin
      Result := INTERNAL_ERROR_CODE;
      Exit;
    end;

    Dec(LBytesLeftToWrite, LBytesWritten);
    Inc(LOffset, LBytesWritten);
  end;

  Result := LOffset - AOffset;
  Log('Result: '+IntToStr(Result));
end;

procedure TIdSSLIOHandlerSocketLibTLS.ConnectClient;
var
  LPassThrough: Boolean;
begin
  inherited;
  Log('- ConnectClient -');

  LPassThrough := fPassThrough;
  fPassThrough := True;
  try
    inherited ConnectClient;
  finally
    fPassThrough := LPassThrough;
  end;

  StartSSL;
end;

function TIdSSLIOHandlerSocketLibTLS.CheckForError(ALastResult: Integer): Integer;
begin
  Log('- CheckForError -');

  if PassThrough then
  begin
    Result := inherited CheckForError(ALastResult);
  end
  else
  begin
    if (ALastResult = INTERNAL_ERROR_CODE) then
    begin
      Result := INTERNAL_ERROR_CODE;
      // send or recv failed
      Log(tls_error(FTLS_CLIENT));
      raise EIdLibTLSError.Create(tls_error(FTLS_CLIENT));
    end;
  end;
end;

procedure TIdSSLIOHandlerSocketLibTLS.RaiseError(AError: Integer);
begin
  Log('- RaiseError -');

  if (PassThrough) or (AError = Id_WSAESHUTDOWN) or (AError = Id_WSAECONNABORTED) or (AError = Id_WSAECONNRESET) then
  begin
    inherited RaiseError(AError);
  end
  else
  begin
    raise EIdLibTLSError.Create(tls_error(FTLS_CLIENT));
  end;
end;

procedure TIdSSLIOHandlerSocketLibTLS.SetPassThrough(const AValue: Boolean);
var
  ret: Integer;
begin
  Log('- SetPassThrough -');
  Log('AValue:'+BoolToStr(AValue));

  if fPassThrough <> AValue then
  begin
    if not AValue then
    begin
      if BindingAllocated then
      begin
        OpenSecureConnection;
      end;
    end
    else
    begin
      repeat
        ret := tls_close(FTLS_CLIENT);

        if ((ret = TLS_WANT_POLLIN) or (ret = TLS_WANT_POLLOUT)) then
        begin
          Log('continue due to '+IntToStr(ret));
          Continue;
        end;

        if ret <> 0 then
        begin
          Log('Cannot close connection!');
          raise EIdLibTLSError.Create('Cannot close connection!');
        end;
        Break;
      until False;
    end;
    fPassThrough := AValue;
  end;
end;

procedure TIdSSLIOHandlerSocketLibTLS.InitComponent;
begin
  inherited InitComponent;
  IsPeer := False;

  Log('- InitComponent -');
  if (tls_init() <> 0) then
  begin
    Log('tls_init failed!');
    raise EIdLibTLSError.Create('tls_init failed!');
  end;

  FTLSConfig := TIdTLSConfig.Create;
  FX509 := TIdX509.Create;
  FOCSPStapling := TIdOCSPStapling.Create;
end;

procedure TIdSSLIOHandlerSocketLibTLS.PeerCertificateCallback;
begin
  DoPeerCertificate(FX509);
end;

procedure TIdSSLIOHandlerSocketLibTLS.DoPeerCertificate(const ACertificate: TIdX509);
begin
  if Assigned(FOnPeerCertificate) then
  begin
    FOnPeerCertificate(ACertificate);
  end;
end;

function TIdSSLIOHandlerSocketLibTLS.VerifyOCSPCallback: Boolean;
var
  lVerifiedOK: Boolean;
begin
  try
    lVerifiedOK := DoVerifyOCSP(FOCSPStapling);
  except
    lVerifiedOK := False;
  end;

  Result := lVerifiedOK;
end;

function TIdSSLIOHandlerSocketLibTLS.DoVerifyOCSP(const AOCSPStaplingResponse: TIdOCSPStapling): Boolean;
begin
  if Assigned(OnVerifyOCSPStapling) then
  begin
    Result := OnVerifyOCSPStapling(AOCSPStaplingResponse);
  end
  else
  begin
    Result := (AOCSPStaplingResponse.CertStaus = TLS_OCSP_CERT_GOOD);
  end;
end;

destructor TIdSSLIOHandlerSocketLibTLS.Destroy;
begin
  Log('- Destroy -');
  tls_free(FTLS_CLIENT);
  FTLSConfig.Free;
  FX509.Free;
  FOCSPStapling.Free;

  inherited Destroy;
end;

procedure TIdSSLIOHandlerSocketLibTLS.Close;
var
  rc: Integer;
begin
  Log('- Close -');

  if not PassThrough then
  begin
    rc := tls_close(FTLS_CLIENT);
    Log(IntToStr(rc));
    if (rc <> 0) then
    begin
      Log(tls_error(FTLS_CLIENT));
      raise EIdLibTLSError.Create(tls_error(FTLS_CLIENT));
    end;
  end;

  inherited Close;
end;

function TIdSSLIOHandlerSocketLibTLS.Clone: TIdSSLIOHandlerSocketBase;
var
  LIO: TIdSSLIOHandlerSocketLibTLS;
begin
  writeln('- Clone -');

  LIO := TIdSSLIOHandlerSocketLibTLS.Create(nil);
  try
    LIO.FTLSConfig.Free;
    LIO.FTLSConfig := Self.FTLSConfig;
  except
    LIO.Free;
    raise;
  end;

  Result := LIO;
end;

procedure TIdSSLIOHandlerSocketLibTLS.StartSSL;
begin
  Log('- StartSSL -');
  Log('PassThrough:'+BoolToStr(PassThrough));

  if not PassThrough then
    OpenSecureConnection;
end;

initialization
{
  RegisterSSL('LibTLS','Indy Pit Crew',
    'Copyright '+Char(169)+' 1993 - 2020'#10#13 +
    'Chad Z. Hower (Kudzu) and the Indy Pit Crew. All rights reserved.',
    'LibreSSL LibTLS Support DLL Delphi interface',
    'http://www.indyproject.org/'#10#13 +
    'Original Author - Bi0T1N',
    TIdSSLIOHandlerSocketLibTLS,
    nil);
  TIdSSLIOHandlerSocketLibTLS.RegisterIOHandler;
}
  // create emtpy file
  AssignFile(LogFile, 'log.txt');
  ReWrite(LogFile);

end.
