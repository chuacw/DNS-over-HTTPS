unit IdTestDohResponseParser;

interface
uses
  IdDNSoverHTTPSResolver;

type

  TIdDoHTestResponseResolver = class(TIdDoHResolver)
  public
    /// <summary> Used to test ParseJSONResponse and FillResult.</summary>
    /// <param name="AResponse">The JSON response to parse.</param>
    /// <param name="QClass">the Query Class.</param>
    function TestResponse(const AResponse: string; QClass: Integer): Boolean;
  end;

implementation

{ TIdDoHResolver }

function TIdDoHTestResponseResolver.TestResponse(const AResponse: string; QClass: Integer): Boolean;
begin
  try
    var
    LResponse := AResponse;
    if LResponse <> '' then
      begin
        var LDNSResponse := ParseJSONResponse(LResponse, FDNSHeader.ID, QClass);
        if Length(LDNSResponse) > 4 then
          FillResult(LDNSResponse);
      end;
    Result := True;
  except
    Result := False;
  end;
end;

end.
