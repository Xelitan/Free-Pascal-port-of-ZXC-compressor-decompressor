{$mode objfpc}{$H+}
program zxcpas;

// Free Pascal port of ZXC - High-performance lossless compression
// ZXC Copyright (c) 2025-2026 Bertrand Lebonnois and contributors.
// Port author: www.xelitan.com
// License: BSD-3-Clause

uses
  SysUtils,
  zxc;

procedure Usage;
begin
  WriteLn('Usage:');
  WriteLn('  zxcpas -c <input> <output>   compress a file');
  WriteLn('  zxcpas -d <input> <output>   decompress a file');
end;

function ReadFile(const Path: string; out Data: PByte; out Size: PtrUInt): Boolean;
var
  F: file;
begin
  Result := False;
  if not FileExists(Path) then
  begin
    WriteLn('Error: file not found: ', Path);
    Exit;
  end;
  AssignFile(F, Path);
  Reset(F, 1);
  Size := FileSize(F);
  if Size = 0 then
  begin
    CloseFile(F);
    WriteLn('Error: input file is empty: ', Path);
    Exit;
  end;
  GetMem(Data, Size);
  BlockRead(F, Data^, Size);
  CloseFile(F);
  Result := True;
end;

function WriteFile(const Path: string; Data: PByte; Size: PtrUInt): Boolean;
var
  F: file;
begin
  Result := False;
  AssignFile(F, Path);
  Rewrite(F, 1);
  BlockWrite(F, Data^, Size);
  CloseFile(F);
  Result := True;
end;

procedure DoCompress(const InPath, OutPath: string);
var
  InData, OutData: PByte;
  InSize, OutBound: PtrUInt;
  Ret: LongInt;
begin
  if not ReadFile(InPath, InData, InSize) then Exit;

  OutBound := ZxcCompressBound(InSize);
  GetMem(OutData, OutBound);

  Ret := ZxcCompress(OutData, OutBound, InData, InSize,
                     Ord(ZXC_LEVEL_DEFAULT), 0);

  if Ret < 0 then
    WriteLn('Compression failed, error: ', Ret)
  else
  begin
    WriteFile(OutPath, OutData, PtrUInt(Ret));
    WriteLn(Format('Compressed %d -> %d bytes (%.1f%%)',
      [InSize, Ret, (1.0 - Ret / InSize) * 100.0]));
  end;

  FreeMem(InData);
  FreeMem(OutData);
end;

procedure DoDecompress(const InPath, OutPath: string);
var
  InData, OutData: PByte;
  InSize, OutSize: PtrUInt;
  DecompSize: Int64;
  Ret: LongInt;
begin
  if not ReadFile(InPath, InData, InSize) then Exit;

  DecompSize := ZxcGetDecompressedSize(InData, InSize);
  if DecompSize < 0 then
  begin
    WriteLn('Error reading decompressed size, code: ', DecompSize);
    FreeMem(InData);
    Exit;
  end;

  OutSize := PtrUInt(DecompSize);
  GetMem(OutData, OutSize);

  Ret := ZxcDecompress(OutData, OutSize, InData, InSize);

  if Ret < 0 then
    WriteLn('Decompression failed, error: ', Ret)
  else
  begin
    WriteFile(OutPath, OutData, PtrUInt(Ret));
    WriteLn(Format('Decompressed %d -> %d bytes', [InSize, Ret]));
  end;

  FreeMem(InData);
  FreeMem(OutData);
end;

begin
  if ParamCount <> 3 then
  begin
    Usage;
    Halt(1);
  end;

  case ParamStr(1) of
    '-c': DoCompress(ParamStr(2), ParamStr(3));
    '-d': DoDecompress(ParamStr(2), ParamStr(3));
  else
    begin
      WriteLn('Unknown option: ', ParamStr(1));
      Usage;
      Halt(1);
    end;
  end;
end.
