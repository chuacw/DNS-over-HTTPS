// chuacw, Singapore

unit IdGoogleDNS;

interface
uses
  IdDNSoverHTTPSResolver;

type

// https://developers.google.com/speed/public-dns/docs/dns-over-https

  /// <summary> Google DNS over HTTPS resolver </summary>
  TIdGoogleDNSResolver = class(TIdDoHResolver)
  protected
    procedure InitComponent; override;
    procedure UpdateURL(var VURL: string); override;
  end;

implementation

//  Use these: A-Z a-z 0-9 - . _ ~ ( ) ' ! * : @ , ;
function GenerateRandomPadding: string;
const
  CPunctuation: array[0..12] of Char=(
    '-',
    '.',
    '_',
    '~',
    '(',
    ')',
    '''',
    '!',
    '*',
    ':',
    '@',
    ',',
    ';'
  );
var
  LRandomVal, I, LClass: Integer;
  Ch: Char;
begin
  SetLength(Result, 16);
  Randomize;
  for I := Low(Result) to High(Result) do
    begin
      LClass := Random(4);
      case LClass of
        0: Ch := Chr(Ord('a')+Random(26));
        1: Ch := Chr(Ord('A')+Random(26));
        2: Ch := Chr(Ord('0')+Random(9));
      else
//      3: // but use it in else so that compiler don't complain
// about Ch not being initialized
        LRandomVal := Random(High(CPunctuation));
        if LRandomVal<High(CPunctuation) then
          Inc(LRandomVal);
        Ch := CPunctuation[LRandomVal];
      end;
      Result[I] := Ch;
    end;
end;

{ TGoogleDNSResolver }

procedure TIdGoogleDNSResolver.InitComponent;
begin
  inherited;
  BootstrapAddress := '';
  // 'https://google-public-dns-a.google.com/resolve'; // this doesn't support DoH
  // Google doesn't support bootstrapping, or querying just using its IP address.
  QueryURL := 'https://dns.google.com/resolve';
  EnablePrivacy := True;
  PreventAttacks := True;
end;

procedure TIdGoogleDNSResolver.UpdateURL(var VURL: string);
var
  LRandomPadding: string;
begin
  inherited;
  if FEnablePrivacy then
    VURL := VURL + '&edns_client_subnet=0.0.0.0/0';
  if FPreventAttacks then
    begin
      LRandomPadding := GenerateRandomPadding;
      VURL := VURL + '&random_padding=' + LRandomPadding;
    end;
end;

end.
