unit ZxcSimple;

interface

uses
  Classes, SysUtils, zxc;

function ZxcCompressStreams(InStr, OutStr: TStream): Integer;
function ZxcDecompressStreams(InStr, OutStr: TStream): Integer;

function ZxcCompressFile(const Infilename, Outfilename: String): Integer;
function ZxcDecompressFile(const Infilename, Outfilename: String): Integer;

function Zxc(Uncompressed: AnsiString): AnsiString;
function UnZxc(Compressed: AnsiString): AnsiString;

implementation

function ZxcCompressStreams(InStr, OutStr: TStream): Integer;
var
  InData, OutData: PByte;
  InSize, OutBound: PtrUInt;
  Ret: LongInt;
begin
  Result := -1;
  InData := nil;
  OutData := nil;

  try
    InSize := InStr.Size - InStr.Position;
    if InSize = 0 then Exit;

    GetMem(InData, InSize);
    InStr.ReadBuffer(InData^, InSize);

    OutBound := ZxcCompressBound(InSize);
    GetMem(OutData, OutBound);

    Ret := ZxcCompress(
      OutData,
      OutBound,
      InData,
      InSize,
      Ord(ZXC_LEVEL_DEFAULT),
      0
    );

    if Ret < 0 then Exit;

    OutStr.WriteBuffer(OutData^, Ret);
    Result := 0;
  except
    Result := -1;
  end;

  if InData <> nil then FreeMem(InData);
  if OutData <> nil then FreeMem(OutData);
end;

function ZxcDecompressStreams(InStr, OutStr: TStream): Integer;
var
  InData, OutData: PByte;
  InSize, OutSize: PtrUInt;
  DecompSize: Int64;
  Ret: LongInt;
begin
  Result := -1;
  InData := nil;
  OutData := nil;

  try
    InSize := InStr.Size - InStr.Position;
    if InSize = 0 then Exit;

    GetMem(InData, InSize);
    InStr.ReadBuffer(InData^, InSize);

    DecompSize := ZxcGetDecompressedSize(InData, InSize);
    if DecompSize < 0 then Exit;

    OutSize := PtrUInt(DecompSize);
    GetMem(OutData, OutSize);

    Ret := ZxcDecompress(
      OutData,
      OutSize,
      InData,
      InSize
    );

    if Ret < 0 then Exit;

    OutStr.WriteBuffer(OutData^, Ret);
    Result := 0;
  except
    Result := -1;
  end;

  if InData <> nil then FreeMem(InData);
  if OutData <> nil then FreeMem(OutData);
end;

function ZxcCompressFile(const Infilename, Outfilename: String): Integer;
var
  InFile: TFileStream;
  OutFile: TFileStream;
begin
  Result := 0;
  InFile := nil;
  OutFile := nil;

  try
    try
      InFile := TFileStream.Create(Infilename, fmOpenRead or fmShareDenyWrite);
    except
      Result := -1;
      Exit;
    end;

    try
      try
        OutFile := TFileStream.Create(Outfilename, fmCreate);
      except
        Result := -3;
        Exit;
      end;

      Result := ZxcCompressStreams(InFile, OutFile);
    finally
      OutFile.Free;
    end;
  finally
    InFile.Free;
  end;
end;

function ZxcDecompressFile(const Infilename, Outfilename: String): Integer;
var
  InFile: TFileStream;
  OutFile: TFileStream;
begin
  Result := 0;
  InFile := nil;
  OutFile := nil;

  try
    try
      InFile := TFileStream.Create(Infilename, fmOpenRead or fmShareDenyWrite);
    except
      Result := -1;
      Exit;
    end;

    try
      try
        OutFile := TFileStream.Create(Outfilename, fmCreate);
      except
        Result := -3;
        Exit;
      end;

      Result := ZxcDecompressStreams(InFile, OutFile);
    finally
      OutFile.Free;
    end;
  finally
    InFile.Free;
  end;
end;

function Zxc(Uncompressed: AnsiString): AnsiString;
var
  InStream, OutStream: TMemoryStream;
begin
  Result := '';
  InStream := TMemoryStream.Create;
  OutStream := TMemoryStream.Create;
  try
    // put data in a stream
    if Length(Uncompressed) > 0 then
      InStream.WriteBuffer(Pointer(Uncompressed)^, Length(Uncompressed));
    InStream.Position := 0;

    // pack
    if ZxcCompressStreams(InStream, OutStream) <> 0 then
      Exit;

    // stream to string
    SetLength(Result, OutStream.Size);
    if OutStream.Size > 0 then
    begin
      OutStream.Position := 0;
      OutStream.ReadBuffer(Pointer(Result)^, OutStream.Size);
    end;
  finally
    OutStream.Free;
    InStream.Free;
  end;
end;

function UnZxc(Compressed: AnsiString): AnsiString;
var
  InStream, OutStream: TMemoryStream;
begin
  Result := '';
  InStream := TMemoryStream.Create;
  OutStream := TMemoryStream.Create;
  try
    // string to stream
    if Length(Compressed) > 0 then
      InStream.WriteBuffer(Pointer(Compressed)^, Length(Compressed));
    InStream.Position := 0;

    // unpack
    if ZxcDecompressStreams(InStream, OutStream) <> 0 then
      Exit;

    // stream to string
    SetLength(Result, OutStream.Size);
    if OutStream.Size > 0 then
    begin
      OutStream.Position := 0;
      OutStream.ReadBuffer(Pointer(Result)^, OutStream.Size);
    end;
  finally
    OutStream.Free;
    InStream.Free;
  end;
end;

end.