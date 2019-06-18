unit InternetDateUtils;

interface

/// <summary> Parses RFC 1123 formatted date/time "Wed, 12 Jun 2019 07:00:53 UTC" to TDateTime.
/// Returns now if it fails to parse, otherwise, returns the parsed date time. </summary>
function RFC1123ToDateTime(const ADateTimeStr: string): TDateTime;
/// <summary> Parses RFC 1123 formatted date/time "Wed, 12 Jun 2019 07:00:53 UTC" to TDateTime.
/// Returns false if it fails to parse. Otherwise, the date is returned in VDateTime. </summary>
function TryRFC1123ToDateTime(const ADateTimeStr: string; out VDateTime: TDateTime): Boolean;

implementation
uses
  System.SysUtils, System.StrUtils;

function RFC1123ToDateTime(const ADateTimeStr: string): TDateTime;
begin
  if not TryRFC1123ToDateTime(ADateTimeStr, Result) then
    Result := Now;
end;

function TryRFC1123ToDateTime(const ADateTimeStr: string; out VDateTime: TDateTime): Boolean;
var
  LDay, LMonth, LYear,
  LHour, LMinute, LSecond: NativeInt;
  LMonthName: string;
begin
  try
    LDay       := StrToInt(Copy(ADateTimeStr, 6, 2));
    LMonthName := Copy(ADateTimeStr, 9, 3);
    LMonth := IndexStr(LMonthName, FormatSettings.ShortMonthNames);
    if LMonth <> -1 then
      Inc(LMonth) else
    begin
      if SameText(LMonthName, 'Jan') then LMonth := 1
      else if SameText(LMonthName, 'Feb') then LMonth := 2
      else if SameText(LMonthName, 'Mar') then LMonth := 3
      else if SameText(LMonthName, 'Apr') then LMonth := 4
      else if SameText(LMonthName, 'May') then LMonth := 5
      else if SameText(LMonthName, 'Jun') then LMonth := 6
      else if SameText(LMonthName, 'Jul') then LMonth := 7
      else if SameText(LMonthName, 'Aug') then LMonth := 8
      else if SameText(LMonthName, 'Sep') then LMonth := 9
      else if SameText(LMonthName, 'Oct') then LMonth := 10
      else if SameText(LMonthName, 'Nov') then LMonth := 11
      else if SameText(LMonthName, 'Dec') then LMonth := 12;
    end;
    LYear   := StrToInt(Copy(ADateTimeStr, 13, 4));
    LHour   := StrToInt(Copy(ADateTimeStr, 18, 2));
    LMinute := StrToInt(Copy(ADateTimeStr, 21, 2));
    LSecond := StrToInt(Copy(ADateTimeStr, 24, 2));
    VDateTime := EncodeDate(LYear, LMonth, LDay) + EncodeTime(LHour, LMinute, LSecond, 0);
    Result := True;
  except
    Result := False;
  end;
end;

end.
