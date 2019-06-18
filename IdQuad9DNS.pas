// chuacw, Singapore

unit IdQuad9DNS;

interface
uses
  IdDNSoverHTTPSResolver;

type

// https://www.quad9.net/doh-quad9-dns-servers/

  /// <summary> Quad9 DNS over HTTPS resolver </summary>
  TIdQuad9DNSResolver = class(TIdDoHResolver)
  protected
    procedure InitComponent; override;
    procedure UpdateURL(var VURL: string); override;
    procedure UpdateAccept; override;
  end;

implementation

{ TQuad9DNSResolver }

procedure TIdQuad9DNSResolver.InitComponent;
begin
  inherited;
  BootstrapAddress := '9.9.9.9';
  QueryURL := 'https://dns9.quad9.net/dns-query';
end;

procedure TIdQuad9DNSResolver.UpdateAccept;
begin
  FHTTP.Request.Accept := 'application/dns-json';
end;

procedure TIdQuad9DNSResolver.UpdateURL(var VURL: string);
begin
  inherited; // inherit the parent behaviour for now...
end;

end.
