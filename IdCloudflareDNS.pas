// chuacw, Singapore

unit IdCloudflareDNS;

interface
uses
  IdDNSoverHTTPSResolver, System.Classes;

type

// https://developers.cloudflare.com/1.1.1.1/dns-over-https/json-format/
  /// <summary> Cloudflare DNS over HTTPS resolver </summary>
  [ComponentPlatforms(pidAllPlatforms)]
  TIdCloudflareDNSResolver = class(TIdDoHResolver)
  protected
    procedure InitComponent; override;
    procedure UpdateURL(var VURL: string); override;
    procedure UpdateAccept; override;
  published
    property DisableValidation;
    property DNSSecOk;
  end;

implementation
uses
  System.SysUtils;

{ TIdCloudflareDNSResolver }

procedure TIdCloudflareDNSResolver.InitComponent;
begin
  inherited;
  BootstrapAddress := ''; // 1.1.1.1 Bootstrap not necessary if QueryURL is using a host IP
  QueryURL := 'https://1.1.1.1/dns-query'; // https://1dot1dot1dot1.cloudflare-dns.com/dns-query
end;

procedure TIdCloudflareDNSResolver.UpdateAccept;
begin
  FHTTP.Request.Accept := 'application/dns-json';
end;

procedure TIdCloudflareDNSResolver.UpdateURL(var VURL: string);
begin
  inherited;
  if DNSSecOk then
    VURL := VURL + '&do=' + LowerCase(BoolToStr(DNSSecOk, True));
  if DisableValidation then
    VURL := VURL + '&cd=' + LowerCase(BoolToStr(DisableValidation, True));
end;

end.
