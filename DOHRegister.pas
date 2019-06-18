unit DOHRegister;

interface

procedure Register;
implementation
uses
  System.Classes, IdCloudflareDNS, IdGoogleDNS, IdQuad9DNS;

procedure Register;
begin
  RegisterComponents('DNS over HTTPS', [TIdCloudflareDNSResolver,
    TIdGoogleDNSResolver, TIdQuad9DNSResolver]);
end;

end.
