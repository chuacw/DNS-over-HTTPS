// chuacw, Singapore

unit IdDNSoverHTTPSResolver;

interface
uses
  IdDNSResolver, IdDNSCommon, IdHTTP, IdGlobal, IdURI;

type
  TIdDoHResolver = class(TIdDNSResolver)
  protected
    // Fot bootstrapping only!
    FURI: TIdURI;

    FQueryURL, FBootstrapAddress: string;
    FHTTP: TIdHTTP;
    FSSLIOHandler: TObject;
    FPreventAttacks,
    FEnablePrivacy, FDisableValidation, FDNSSecOk: Boolean;
    FQueryValues: TArray<Integer>;
    FQueryStrings: TArray<string>;
    procedure SetQueryURL(const Value: string);
  protected
    procedure InitComponent; override;
    /// <summary> Provides opportunity to update the URL before sending it to the
    /// DNS resolver, so descendants can set additional parameters on the URL</summary>
    procedure UpdateURL(var VURL: string); virtual;
    /// <summary> Allows descendants to update the HTTP.Request.Accept string. </summary>
    procedure UpdateAccept; virtual;
    class function ParseJSONResponse(const AResponse: string; const ID: UInt16; AQueryClass: UInt16): TIdBytes; static;
  public
    destructor Destroy; override;
    procedure Resolve(const ADomainName: string; SOARR : TIdRR_SOA = nil; QClass: integer = Class_IN);
    procedure AddQueryType(const AQueryType: NativeUInt); overload;
    procedure AddQueryType(const AQueryType: string); overload;
    property BootstrapAddress: string read FBootstrapAddress write FBootstrapAddress;
    property QueryURL: string read FQueryURL write SetQueryURL;
    property DNSSecOk: Boolean read FDNSSecOk write FDNSSecOk;
    property DisableValidation: Boolean read FDisableValidation write FDisableValidation;
    property EnablePrivacy: Boolean read FEnablePrivacy write FEnablePrivacy;
    property PreventAttacks: Boolean read FPreventAttacks write FPreventAttacks;
  end;

  TDoHResolverClass = class of TIdDoHResolver;

implementation
uses
  System.JSON, IdStack, System.StrUtils, System.SysUtils, InternetDateUtils,
  System.DateUtils, IdGlobalProtocols, IdSSLOpenSSL, IdExceptionCore;

type
  TIdHTTPKeepAliveResponse = class(TIdHTTP)
  private
    FHTTPProto: TIdHTTPProtocol;
  protected
    function CreateProtocol: TIdHTTPProtocol; override;
    procedure InitComponent; override;
    property HTTPProto: TIdHTTPProtocol read FHTTPProto;
  end;

function TIdHTTPKeepAliveResponse.CreateProtocol: TIdHTTPProtocol;
begin
  Result := inherited;
  Result.Response.KeepAlive := True;
end;

procedure TIdHTTPKeepAliveResponse.InitComponent;
begin
  inherited;
  ProtocolVersion := pv1_1;
end;

// See https://developers.cloudflare.com/1.1.1.1/dns-over-https/json-format/

{ TIdDoHResolver }

procedure TIdDoHResolver.AddQueryType(const AQueryType: NativeUInt);
begin
  FQueryValues := FQueryValues + [AQueryType];
end;

procedure TIdDoHResolver.AddQueryType(const AQueryType: string);
begin
  FQueryStrings := FQueryStrings + [AQueryType];
end;

destructor TIdDoHResolver.Destroy;
begin
  FURI.Free;
  FSSLIOHandler.Free;
  FHTTP.Free;
  inherited;
end;

procedure TIdDoHResolver.InitComponent;
begin
  inherited;
  FBootstrapAddress := '1.1.1.1'; // Cloudflare
end;

function LengthToBytes(const ALength: Integer): TIdBytes;
begin
  if ALength < High(Byte) then
    Result := ToBytes(UInt8(ALength)) else
  if ALength < High(UInt16) then
    Result := ToBytes(UInt16(ALength)) else
  if ALength < High(Integer) then
    Result := ToBytes(UInt32(ALength));
end;

class function TIdDoHResolver.ParseJSONResponse(const AResponse: string; const ID: UInt16; AQueryClass: UInt16): TIdBytes;
const
  TypeCode_RRSIG = 46;
  CTypeCodes: array[TQueryRecordTypes] of UInt16 = (
    TypeCode_A,
    TypeCode_NS,
    TypeCode_MD,
    TypeCode_MF,
    TypeCode_CName,
    TypeCode_SOA,
    TypeCode_MB,
    TypeCode_MG,
    TypeCode_MR,
    TypeCode_NULL,
    TypeCode_WKS,
    TypeCode_PTR,
    TypeCode_HINFO,
    TypeCode_MINFO,
    TypeCode_MX,
    TypeCode_TXT,
//    TypeCode_RP, TypeCode_AFSDB, TypeCode_X25, TypeCode_ISDN,
    TypeCode_RT, TypeCode_NSAP, TypeCode_NSAP_PTR, TypeCode_SIG,
//    TypeCode_KEY, TypeCode_PX, TypeCode_QPOS,
    TypeCode_AAAA,
//    TypeCode_LOC, TypeCode_NXT, TypeCode_R31, TypeCode_R32,
    TypeCode_Service,
//    TypeCode_R34,
    TypeCode_NAPTR,
//    TypeCode_KX,
    TypeCode_CERT,
    TypeCode_V6Addr,
    TypeCode_DNAME,
    TypeCode_R40,
    TypeCode_OPTIONAL,
    TypeCode_IXFR,
    TypeCode_AXFR,
    TypeCode_STAR
//    TypeCode_Error
    );
var
  LJSONObj, LQuestionObj, LAnswerObj: TJSONObject;
  BitCode, QDCount, ANCount, NSCount, ARCount: UInt16;
  LQuestions, LAnswers, LAuthority, LAdditional: TJSONArray;
  LMX, LSOA, LRRSIG: TArray<string>;
  LMName, LRName, LDomainName: string; LNameValue: string; LDataValue: string;
  LSOASerial, LSOARefresh, LSOARetry, LSOAExpire, LSOAMinimumTTL: UInt32;
  RD_Length, LTypeValue: UInt16; LClassValue: Word;
  LTTLValue: UInt32;
  LData, RData: TIdBytes;
  I, J: UInt16;
  LStatus: Word;
  /// <summary>Truncated bit was set </summary>
  TC,
  /// <summary>Recursive Desired bit was set </summary>
  RD,
  /// <summary>Recursion available bit was set </summary>
  RA,
  /// <summary> Answer verified with DNSSEC </summary>
  AD,
  /// <summary> if true, client has asked to disable DNSSEC validation </summary>
  CD: Boolean;
  VAddress: TIdIPv6Address;
begin
  Result := nil;
  LJSONObj := TJSONObject.ParseJSONValue(AResponse) as TJSONObject;
  try
    LJSONObj.TryGetValue<UInt16>('Status', LStatus);
    LJSONObj.TryGetValue<Boolean>('TC', TC);
    LJSONObj.TryGetValue<Boolean>('RD', RD);
    LJSONObj.TryGetValue<Boolean>('RA', RA);
    LJSONObj.TryGetValue<Boolean>('AD', AD);
    LJSONObj.TryGetValue<Boolean>('CD', CD);
    BitCode := 0; QDCount := 0; ANCount := 0; NSCount := 0; ARCount := 0;
    if LJSONObj.TryGetValue('Question', LQuestions) then
      QDCount := LQuestions.Count;
    if LJSONObj.TryGetValue('Answer', LAnswers) then
      ANCount := LAnswers.Count;
    if LJSONObj.TryGetValue('Authority', LAuthority) then
      NSCount := LAuthority.Count;
    if LJSONObj.TryGetValue('Additional', LAdditional) then
      ARCount := LAdditional.Count;

    Result := ToBytes(GStack.HostToNetwork(ID)) +
              ToBytes(GStack.HostToNetwork(BitCode)) +
              ToBytes(GStack.HostToNetwork(QDCount)) +
              ToBytes(GStack.HostToNetwork(ANCount)) +
              ToBytes(GStack.HostToNetwork(NSCount)) +
              ToBytes(GStack.HostToNetwork(ARCount));

    if QDCount > 0 then
      begin
        for I := 0 to QDCount-1 do
          begin
            LQuestionObj := LQuestions.Items[I] as TJSONObject;
            LDomainName := LQuestionObj.GetValue<string>('name');
            LTypeValue := LQuestionObj.GetValue<UInt16>('type');

            Result := Result + DomainNameToDNSStr(LDomainName) +
                          ToBytes(GStack.HostToNetwork(LTypeValue)) +
                        ToBytes(GStack.HostToNetwork(UInt16(AQueryClass))); // 0 as class
          end;
      end;

    if ANCount > 0 then
      begin
        for I := 0 to ANCount-1 do
          begin
            RData := nil;
            LAnswerObj := LAnswers.Items[I] as TJSONObject;
            LNameValue := LAnswerObj.GetValue<string>('name');
            LTypeValue := LAnswerObj.GetValue<UInt16>('type');
            // Class? What value?
            LClassValue := 0;

            LTTLValue  := LAnswerObj.GetValue<UInt32>('TTL');
            LDataValue := LAnswerObj.GetValue<string>('data'); // IP address

            case LTypeValue of
              TypeCode_SOA: begin
                LSOA := TArray<string>(SplitString(LDataValue, ' '));
                LMName := LSOA[0];
                LRName := LSOA[1];
                LSOASerial := StrToUInt(LSOA[2]);
                LSOARefresh := StrToUInt(LSOA[3]);
                LSOARetry := StrToUInt(LSOA[4]);
                LSOAExpire := StrToUIntDef(LSOA[5], 0);
                if LSOAExpire = 0 then
                  begin
                    var LSOAExpireDT: TDateTime := 0;
                    if TryRFC1123ToDateTime(LSOA[5], LSOAExpireDT) then
                      begin
                        var MSecsSince1970 := MilliSecondsBetween(LSOAExpireDT, EncodeDate(1970, 1, 1));
                        LSOAExpire := MSecsSince1970;
                      end;
                  end;
                LSOAMinimumTTL := StrToUInt(LSOA[6]);

                RData := DomainNameToDNSStr(LMName) + DomainNameToDNSStr(LRName) +
                  ToBytes(GStack.HostToNetwork(LSOASerial)) +
                  ToBytes(GStack.HostToNetwork(LSOARefresh)) +
                  ToBytes(GStack.HostToNetwork(LSOARetry)) +
                  ToBytes(GStack.HostToNetwork(LSOAExpire)) +
                  ToBytes(GStack.HostToNetwork(LSOAMinimumTTL));
              end;
              TypeCode_TXT: begin
                RData := NormalStrToDNSStr(LDataValue) + [0];
              end;
              TypeCode_NAPTR: begin
                var LOrder: UInt16 := 11;
                var LPref:  UInt16 := 22;
                var LFlags: string := 'FLAG';
                var LService: string := 'Service';
                var LRegExp: string  := 'REGEXP';
                var LReplacement: string := 'REPLACE';

                RData := ToBytes(GStack.NetworkToHost(LOrder)) +
                         ToBytes(GStack.NetworkToHost(LPref)) +
                         NormalStrToDNSStr(LFlags) +
                         NormalStrToDNSStr(LService) +
                         NormalStrToDNSStr(LRegExp) +
                         NormalStrToDNSStr(LReplacement);
              end;
              TypeCode_HINFO: begin
                var LCPU := NormalStrToDNSStr('AMD');
                var LOS  := NormalStrToDNSStr('Windows');
                RData := LCPU + LOS + [0];
              end;
              TypeCode_A: begin
                // FIPAddress := MakeUInt32IntoIPv4Address(GStack.NetworkToHost(OrdFourByteToUInt32(RData[0], RData[1], RData[2], RData[3])));
                if IsValidIP(LDataValue) then
                  RData := ToBytes(GStack.HostToNetwork(IPv4ToUInt32(LDataValue)));
              end;
              TypeCode_NS,
              TypeCode_CName: begin
                RData := DomainNameToDNSStr(LDataValue);
              end;
              TypeCode_MX: begin
                LMX := SplitString(LDataValue, ' ');
                var LPreference: UInt16 := StrToUInt(LMX[0]);
                var LExchangeServer := LMX[1];
                RData := ToBytes(GStack.HostToNetwork(LPreference)) +
                  DomainNameToDNSStr(LExchangeServer);
              end;
              TypeCode_AAAA: begin
                if IsValidIP(LDataValue) and (Length(LDataValue)>15) then
                  begin
                    IPv6ToIdIPv6Address(LDataValue, VAddress);
                    RData := nil;
                    for J := 0 to 7 do
                      RData := RData + ToBytes(GStack.HostToNetwork(VAddress[J]));
                  end;
              end;
              TypeCode_RRSIG: begin // RRSIG
  //      "Expires": "Wed, 12 Jun 2019 06:32:03 UTC",
  //      "data": "SOA 8 2 3600 20190622141844 20190601215824 23689 example.com. cbLvbWFP1gPLnXTLMZOwzynw9dd0hrojJcw0Xody31u+zqXPLxclFsswKzUu972875Hzyo18jYFeQ52gwQ0voRT15HUfDiBtfR/sXJl0AgNoBiF3zo12ehzS/rvDZNDoRQjNFsBcCJnKSg+tqWft3xA/s8g1TUCSjnfULql/Ykk="
  // RRSIG for example.com
  //      "data": "nsec 8 2 3600 1561200044 1559390304 23689 example.com. hBT2zBFJlU5EUkdSfNwtueAWnMa7/BmkCGHDypBxmR5po5huPFQppIr87N7pbfhVHrhDxoZMktALYilVuCo0yeJY0ZwQZWw8XiIccuQorrhvIj4bywQ/7ol0F033CUpGAZb3JxzfdKh9CDY1Ma+0/qadYH1xSU18juYH3G/2GHw="
                var LExpiresDT: string; var LExpiresUInt: UInt32 := 0;
                var LExpires: TDateTime := 0;
                if LAnswerObj.TryGetValue<string>('Expires', LExpiresDT) then
                  TryRFC1123ToDateTime(LExpiresDT, LExpires);

                LRRSIG := SplitString(LDataValue, ' ');
                var LDNSTypeCovered      := LRRSIG[0];  // nsec
                var LAlgorithmCovered    := LRRSIG[1];  // 8
                var LNumOfLabels         := LRRSIG[2];  // 2
                var LOriginalTTL         := LRRSIG[3];  // 3600
                var LSignatureExpiration := LRRSIG[4];  // 1561200044
                var LSignatureInception  := LRRSIG[5];  // 1559390304
                var LKeyTag              := LRRSIG[6];  // 23689
                var LSignerName          := LRRSIG[7];  // example.com
                var LSignature           := LRRSIG[8];  // hBT2zBFJlU5EUk....

                RData := [0];

  //              RData := NormalStrToDNSStr(LMName) + NormalStrToDNSStr(LRName) +
  //                ToBytes(GStack.HostToNetwork(LSOASerial)) +
  //                ToBytes(GStack.HostToNetwork(LSOARefresh)) +
  //                ToBytes(GStack.HostToNetwork(LSOARetry)) +
  //                ToBytes(GStack.HostToNetwork(LSOAExpire)) +
  //                ToBytes(GStack.HostToNetwork(LSOAMinimumTTL));
  //
  //              RD_Length := Length(RData);
              end;
            else
              raise Exception.Create('Unhandled type!');
            end;

            RD_Length := Length(RData);

            Result := Result + DomainNameToDNSStr(LNameValue) +
              ToBytes(GStack.HostToNetwork(LTypeValue)) +
              ToBytes(GStack.HostToNetwork(LClassValue)) +
              ToBytes(GStack.HostToNetwork(LTTLValue)) +
              ToBytes(GStack.HostToNetwork(RD_Length)) + RData;
          end;
      end;

    if NSCount > 0 then
      begin
        for I := 0 to NSCount-1 do
          begin
            RData := nil;
            LAnswerObj := LAuthority.Items[I] as TJSONObject;
            LNameValue := LAnswerObj.GetValue<string>('name');
            LTypeValue := LAnswerObj.GetValue<UInt16>('type');
            // Class? What value?
            LClassValue := 0;

            LTTLValue  := LAnswerObj.GetValue<UInt32>('TTL');
            LDataValue := LAnswerObj.GetValue<string>('data');
  // "jule.ns.cloudflare.com. dns.cloudflare.com. 2031180241 10000 2400 604800 3600"
  // MNAME                   RNAME               Serial     Refresh Retry Expire MinimumTTL

            case LTypeValue of
              TypeCode_SOA: begin
                LSOA := SplitString(LDataValue, ' ');
                LMName := LSOA[0];
                LRName := LSOA[1];
                LSOASerial := StrToUInt(LSOA[2]);
                LSOARefresh := StrToUInt(LSOA[3]);
                LSOARetry := StrToUInt(LSOA[4]);
                LSOAExpire := StrToUIntDef(LSOA[5], 0);
                if LSOAExpire = 0 then
                  begin
                    var LSOAExpireDT: TDateTime := 0;
                    if TryRFC1123ToDateTime(LSOA[5], LSOAExpireDT) then
                      begin
                        var MSecsSince1970 := MilliSecondsBetween(LSOAExpireDT, EncodeDate(1970, 1, 1));
                        LSOAExpire := MSecsSince1970;
                      end;
                  end;
                LSOAMinimumTTL := StrToUInt(LSOA[6]);

                RData := DomainNameToDNSStr(LMName) + DomainNameToDNSStr(LRName) +
                  ToBytes(GStack.HostToNetwork(LSOASerial)) +
                  ToBytes(GStack.HostToNetwork(LSOARefresh)) +
                  ToBytes(GStack.HostToNetwork(LSOARetry)) +
                  ToBytes(GStack.HostToNetwork(LSOAExpire)) +
                  ToBytes(GStack.HostToNetwork(LSOAMinimumTTL));

              end;
              TypeCode_RRSIG: begin // RRSIG
  //      "Expires": "Wed, 12 Jun 2019 06:32:03 UTC",
  //      "data": "SOA 8 2 3600 20190622141844 20190601215824 23689 example.com. cbLvbWFP1gPLnXTLMZOwzynw9dd0hrojJcw0Xody31u+zqXPLxclFsswKzUu972875Hzyo18jYFeQ52gwQ0voRT15HUfDiBtfR/sXJl0AgNoBiF3zo12ehzS/rvDZNDoRQjNFsBcCJnKSg+tqWft3xA/s8g1TUCSjnfULql/Ykk="
                var LExpiresDT: string; var LExpiresUInt: UInt32 := 0;
                var LExpires: TDateTime := 0;
                if LAnswerObj.TryGetValue<string>('Expires', LExpiresDT) then
                  TryRFC1123ToDateTime(LExpiresDT, LExpires);

                LSOA := SplitString(LDataValue, ' ');
                LSOASerial := 0;
                LSOARefresh := 0;
                LSOARetry := 0;
                LSOAExpire := 0;
                LSOAMinimumTTL := 0;

                LMName := ''; LRName := '';
                RData := NormalStrToDNSStr(LMName) + NormalStrToDNSStr(LRName) +
                  ToBytes(GStack.HostToNetwork(LSOASerial)) +
                  ToBytes(GStack.HostToNetwork(LSOARefresh)) +
                  ToBytes(GStack.HostToNetwork(LSOARetry)) +
                  ToBytes(GStack.HostToNetwork(LSOAExpire)) +
                  ToBytes(GStack.HostToNetwork(LSOAMinimumTTL));

              end;
              47: begin
  //      "Expires": "Wed, 12 Jun 2019 06:32:03 UTC",
  //      "data": "www.example.com. A NS SOA TXT AAAA RRSIG NSEC DNSKEY"
                var LExpiresDT: string; var LExpiresUInt: UInt32 := 0;
                var LExpires: TDateTime := 0;
                if LAnswerObj.TryGetValue<string>('Expires', LExpiresDT) then
                  TryRFC1123ToDateTime(LExpiresDT, LExpires);
                LDataValue := LAnswerObj.GetValue<string>('data');

                LSOASerial := 0;
                LSOARefresh := 0;
                LSOARetry := 0;
                LSOAExpire := 0;
                LSOAMinimumTTL := 0;

                LMName := ''; LRName := '';
                RData := NormalStrToDNSStr(LMName) + NormalStrToDNSStr(LRName) +
                  ToBytes(GStack.HostToNetwork(LSOASerial)) +
                  ToBytes(GStack.HostToNetwork(LSOARefresh)) +
                  ToBytes(GStack.HostToNetwork(LSOARetry)) +
                  ToBytes(GStack.HostToNetwork(LSOAExpire)) +
                  ToBytes(GStack.HostToNetwork(LSOAMinimumTTL));

              end;
            else
              raise Exception.Create('Unhandled type!');
            end;

            RD_Length := Length(RData);

            Result := Result + DomainNameToDNSStr(LNameValue) +
              ToBytes(GStack.HostToNetwork(LTypeValue)) +
              ToBytes(GStack.HostToNetwork(LClassValue)) +
              ToBytes(GStack.HostToNetwork(LTTLValue)) +
              ToBytes(GStack.HostToNetwork(RD_Length)) +
              RData;
          end;
      end;

    if ARCount > 0 then
      begin
        for I := 0 to NSCount-1 do
          begin

          end;
      end;

  finally
    LJSONObj.Free;
  end;
end;

procedure TIdDoHResolver.Resolve(const ADomainName: string; SOARR: TIdRR_SOA;
  QClass: integer);
const
  CQueryTypes: array[qtA..qtSTAR] of string = (
      'A',
      'NS',
      'MD',
      'MF',
      'Name',
      'SOA',
      'MB',
      'MG',
      'MR',
      'NULL',
      'WKS',
      'PTR',
      'HINFO',
      'MINFO',
      'MX',
      'TXT',
      'RT',
      'NSAP',
      'NSAP_PTR',
      'SIG',
      'AAAA',
      'SRV',
      'NAPTR',
      'CERT',
      'V6Addr',
      'DName',
      'R40',
      'Optional',
      'IXFR',
      'AXFR',
      'STAR'
  );
var
  LSucceeded: Boolean;
  LTryCount: Integer;
  LURL,
  LType, LResponse: string;
  LQueryType: TQueryRecordTypes;
  LSSLIOHandler: TIdSSLIOHandlerSocketOpenSSL;
  LDNSResponse: TIdBytes;
begin
  if not Assigned(FHTTP) then
    begin
      FHTTP := TIdHTTPKeepAliveResponse.Create(Self);
    end;
  if not Assigned(FSSLIOHandler) then
    begin
      LSSLIOHandler := TIdSSLIOHandlerSocketOpenSSL.Create(FHTTP);
      LSSLIOHandler.SSLOptions.Method := sslvSSLv23;
      LSSLIOHandler.SSLOptions.VerifyMode := [];
      LSSLIOHandler.SSLOptions.VerifyDepth := 2;
      FSSLIOHandler := LSSLIOHandler;
      FHTTP.IOHandler := LSSLIOHandler;
    end;
  LTryCount := 0; LSucceeded := False;
  repeat
    LResponse := ''; LType := '';
    UpdateAccept;
    FHTTP.HTTPOptions := FHTTP.HTTPOptions + [hoKeepOrigProtocol];
    FHTTP.Request.Connection := 'keep-alive';
    if TIdHTTPKeepAliveResponse(FHTTP).HTTPProto <> nil then
      TIdHTTPKeepAliveResponse(FHTTP).HTTPProto.Response.KeepAlive := True;
    if QueryType <> [] then
      begin
        for LQueryType in QueryType do
          begin
            if LQueryType < High(TQueryRecordTypes) then
              LType := Format('%s&type=%s', [LType, CQueryTypes[LQueryType]]) else
              LType := Format('%s&type=%d', [LType, Ord(LQueryType)]);
          end;
      end else
    if FQueryValues <> nil then
      begin
        for var LQueryValue in FQueryValues do
          begin
            LType := Format('%s&type=%d', [LType, LQueryValue]);
          end;
        FQueryValues := nil;
      end else
    if FQueryStrings <> nil then
      begin
        for var LQueryValue in FQueryStrings do
          begin
            LType := Format('%s&type=%s', [LType, LQueryValue]);
          end;
        FQueryStrings := nil;
      end;
    if LType = '' then
      raise EIdDnsResolverError.Create('Need to specify QueryType!');
    LURL := Format('%s?name=%s%s', [FQueryURL, ADomainName, LType]);
    UpdateURL(LURL);
    try
      Inc(LTryCount);
      LResponse := FHTTP.Get(LURL);
      if LResponse <> '' then
        begin
          LDNSResponse := ParseJSONResponse(LResponse, FDNSHeader.ID, QClass);
          if Length(LDNSResponse) > 4 then
            FillResult(LDNSResponse);
        end;
        LSucceeded := True;
    except
      on E: Exception do // failed to load SSL library or some other thingy?
    end;
  until (LTryCount>3) or (LSucceeded);
end;

procedure TIdDoHResolver.SetQueryURL(const Value: string);
var
  LURL: string;
begin
  if not Value.StartsWith('http') then
    LURL := 'https://' + Value else
    LURL := Value;
  FQueryURL := LURL;

  if BootstrapAddress = '' then
    Exit;

// Try bootstrapping silently...
  try
    if not Assigned(FURI) then
      FURI := TIdURI.Create(FQueryURL) else
      FURI.URI := FQueryURL;
    if not GStack.IsIP(FURI.Host) then
      begin
        QueryResult.Clear;
        inherited Host := BootstrapAddress;
        QueryType := [qtA];
        var LHostName := FURI.Host;
        inherited Resolve(LHostName);
        if QueryResult.Count > 0 then
          begin
            for var I := 0 to QueryResult.Count-1 do
              if QueryResult[I] is TARecord then
                begin
                 var LARecord := TARecord(QueryResult[I]);
                 FURI.Host := LARecord.IPAddress;
                 FQueryURL := FURI.URI;
                 Break;
                end;
          end;
      end;
  except
    // keep quiet about failure to bootstrap
  end;
end;

procedure TIdDoHResolver.UpdateAccept;
begin
  FHTTP.Request.Accept := 'application/dns+json';
end;

procedure TIdDoHResolver.UpdateURL(var VURL: string);
begin
end;

end.
