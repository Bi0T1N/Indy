program test;

{$mode Delphi}

// fpc -O3 -FiCore -Fu* test.pas

uses
  SysUtils, IdSSLLibTLS, IdSSLLibTLSHeaders, IdHTTP;


type
  TMyClass = class(TObject)
  public
    procedure MyVerifyPeer(const ACertificate: TIdX509);
  end;

var
  http: TIdHTTP;
  resp: String;
  tlshandler: TIdSSLIOHandlerSocketLibTLS;
  flength, i: Integer;
  MyClass: TMyClass;

procedure TMyClass.MyVerifyPeer(const ACertificate: TIdX509);
begin
  writeln('!! X509 event callback start !!');
  writeln(ACertificate.Issuer);
  writeln(ACertificate.Subject);
  writeln('!! X509 event callback end !!');
end;

begin
  writeln('-> loading');
  Load;

  writeln('-> output possible failures');
  writeln(WhichFailedToLoad);

  http := TIdHTTP.Create;
  MyClass := TMyClass.Create;
  try
    tlshandler := TIdSSLIOHandlerSocketLibTLS.Create;
    tlshandler.TLSContext.TLSVersions := [tlsvTLSv1_2, tlsvTLSv1_3];
    //tlshandler.TLSContext.UseOCSPStapling := True; // <-- seems to be not working atm
	  tlshandler.TLSContext.UseOCSPStapling := False; // <--
    tlshandler.OnPeerCertificate := MyClass.MyVerifyPeer;
    http.IOHandler := tlshandler;
    resp := http.Get('https://api.ipify.org/');
    //resp := http.Get('https://www.google.com/');
    //resp := http.Get('https://webhook.site/f17d66f7-694e-4dd6-9a2d-4cffea8d6112');
    //resp := http.Get('https://blog.cloudflare.com/high-reliability-ocsp-stapling/');
    //resp := http.Get('https://www.keycdn.com/support/ocsp-stapling');
  
    writeln('-- X509 infos --');
    writeln(' CertProvided: '+BoolToStr(tlshandler.X509.CertificateProvided, True));
    writeln(' CertAsSHA256: '+tlshandler.X509.CertAsSHA256);
    {$IFNDEF WINDOWS}
      writeln(' CertificateAsPEM:');
      writeln(tlshandler.X509.CertificateAsPEM);
    {$ENDIF}
    writeln(' Issuer: '+tlshandler.X509.Issuer);
    writeln(' Subject: '+tlshandler.X509.Subject);
    writeln(' notBefore: '+DateToStr(tlshandler.X509.notBefore));
    writeln(' notAfter: '+DateToStr(tlshandler.X509.notAfter));

    writeln('-- response --');
    writeln(resp);
  finally
    http.Free;
    MyClass.Free;
  end;

  writeln('-> unloading');
  Unload;

  readln;
end.
