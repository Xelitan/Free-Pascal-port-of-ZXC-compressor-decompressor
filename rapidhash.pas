unit rapidhash;
//Free Pascal port of rapidhash V3
//Rapidhash created by Nicolas De Carli
//Author of the port: www.xelitan.com
//License: MIT


{$mode objfpc}{$H+}
{$inline on}
{$pointermath on}

interface

uses
  SysUtils;

type
  TRapidSecret = array[0..7] of QWord;

const
  RapidSecret: TRapidSecret = (
    QWord($2D358DCCAA6C78A5),
    QWord($8BB84B93962EACC9),
    QWord($4B33A62ED433D4A3),
    QWord($4D5A2DA51DE1AA47),
    QWord($A0761D6478BD642F),
    QWord($E7037ED1A0B428DB),
    QWord($90ED1765281C388C),
    QWord($AAAAAAAAAAAAAAAA)
  );

procedure RapidMum(var A, B: QWord); inline;
function RapidMix(A, B: QWord): QWord; inline;
function RapidRead64(P: PByte): QWord; inline;
function RapidRead32(P: PByte): QWord; inline;

function RapidHashInternal(Key: Pointer; Len: SizeUInt; Seed: QWord; const Secret: TRapidSecret): QWord;
function RapidHashMicroInternal(Key: Pointer; Len: SizeUInt; Seed: QWord; const Secret: TRapidSecret): QWord;
function RapidHashNanoInternal(Key: Pointer; Len: SizeUInt; Seed: QWord; const Secret: TRapidSecret): QWord;

function RapidHashWithSeed(Key: Pointer; Len: SizeUInt; Seed: QWord): QWord; overload;
function RapidHash(const S: RawByteString): QWord; overload;
function RapidHash(const Buffer; Len: SizeUInt): QWord; overload;

function RapidHashMicroWithSeed(Key: Pointer; Len: SizeUInt; Seed: QWord): QWord; overload;
function RapidHashMicro(const S: RawByteString): QWord; overload;
function RapidHashMicro(const Buffer; Len: SizeUInt): QWord; overload;

function RapidHashNanoWithSeed(Key: Pointer; Len: SizeUInt; Seed: QWord): QWord; overload;
function RapidHashNano(const S: RawByteString): QWord; overload;
function RapidHashNano(const Buffer; Len: SizeUInt): QWord; overload;

implementation

procedure RapidMum(var A, B: QWord); inline;
var
  HA, HB, LA, LB: QWord;
  RH, RM0, RM1, RL, T, C: QWord;
  LoPart, HiPart: QWord;
begin
  HA := A shr 32;
  HB := B shr 32;
  LA := LongWord(A);
  LB := LongWord(B);

  RH := HA * HB;
  RM0 := HA * LB;
  RM1 := HB * LA;
  RL := LA * LB;

  T := RL + (RM0 shl 32);
  C := Ord(T < RL);
  LoPart := T + (RM1 shl 32);
  Inc(C, Ord(LoPart < T));
  HiPart := RH + (RM0 shr 32) + (RM1 shr 32) + C;

  {$ifdef RAPIDHASH_PROTECTED}
  A := A xor LoPart;
  B := B xor HiPart;
  {$else}
  A := LoPart;
  B := HiPart;
  {$endif}
end;

function RapidMix(A, B: QWord): QWord; inline;
begin
  RapidMum(A, B);
  Result := A xor B;
end;

function RapidRead64(P: PByte): QWord; inline;
begin
  Result :=
    QWord(P[0]) or
    (QWord(P[1]) shl 8) or
    (QWord(P[2]) shl 16) or
    (QWord(P[3]) shl 24) or
    (QWord(P[4]) shl 32) or
    (QWord(P[5]) shl 40) or
    (QWord(P[6]) shl 48) or
    (QWord(P[7]) shl 56);
end;

function RapidRead32(P: PByte): QWord; inline;
begin
  Result :=
    QWord(P[0]) or
    (QWord(P[1]) shl 8) or
    (QWord(P[2]) shl 16) or
    (QWord(P[3]) shl 24);
end;

function RapidHashInternal(Key: Pointer; Len: SizeUInt; Seed: QWord; const Secret: TRapidSecret): QWord;
var
  P: PByte;
  A, B: QWord;
  I: SizeUInt;
  See1, See2, See3, See4, See5, See6: QWord;
begin
  P := PByte(Key);
  Seed := Seed xor RapidMix(Seed xor Secret[2], Secret[1]);
  A := 0;
  B := 0;
  I := Len;

  if Len <= 16 then
  begin
    if Len >= 4 then
    begin
      Seed := Seed xor Len;
      if Len >= 8 then
      begin
        A := RapidRead64(P);
        B := RapidRead64(P + Len - 8);
      end
      else
      begin
        A := RapidRead32(P);
        B := RapidRead32(P + Len - 4);
      end;
    end
    else if Len > 0 then
    begin
      A := (QWord(P[0]) shl 45) or QWord(P[Len - 1]);
      B := QWord(P[Len shr 1]);
    end;
  end
  else
  begin
    if Len > 112 then
    begin
      See1 := Seed;
      See2 := Seed;
      See3 := Seed;
      See4 := Seed;
      See5 := Seed;
      See6 := Seed;

      repeat
        Seed := RapidMix(RapidRead64(P) xor Secret[0], RapidRead64(P + 8) xor Seed);
        See1 := RapidMix(RapidRead64(P + 16) xor Secret[1], RapidRead64(P + 24) xor See1);
        See2 := RapidMix(RapidRead64(P + 32) xor Secret[2], RapidRead64(P + 40) xor See2);
        See3 := RapidMix(RapidRead64(P + 48) xor Secret[3], RapidRead64(P + 56) xor See3);
        See4 := RapidMix(RapidRead64(P + 64) xor Secret[4], RapidRead64(P + 72) xor See4);
        See5 := RapidMix(RapidRead64(P + 80) xor Secret[5], RapidRead64(P + 88) xor See5);
        See6 := RapidMix(RapidRead64(P + 96) xor Secret[6], RapidRead64(P + 104) xor See6);
        Inc(P, 112);
        Dec(I, 112);
      until I <= 112;

      Seed := Seed xor See1;
      See2 := See2 xor See3;
      See4 := See4 xor See5;
      Seed := Seed xor See6;
      See2 := See2 xor See4;
      Seed := Seed xor See2;
    end;

    if I > 16 then
    begin
      Seed := RapidMix(RapidRead64(P) xor Secret[2], RapidRead64(P + 8) xor Seed);
      if I > 32 then
      begin
        Seed := RapidMix(RapidRead64(P + 16) xor Secret[2], RapidRead64(P + 24) xor Seed);
        if I > 48 then
        begin
          Seed := RapidMix(RapidRead64(P + 32) xor Secret[1], RapidRead64(P + 40) xor Seed);
          if I > 64 then
          begin
            Seed := RapidMix(RapidRead64(P + 48) xor Secret[1], RapidRead64(P + 56) xor Seed);
            if I > 80 then
            begin
              Seed := RapidMix(RapidRead64(P + 64) xor Secret[2], RapidRead64(P + 72) xor Seed);
              if I > 96 then
                Seed := RapidMix(RapidRead64(P + 80) xor Secret[1], RapidRead64(P + 88) xor Seed);
            end;
          end;
        end;
      end;
    end;

    A := RapidRead64(P + I - 16) xor I;
    B := RapidRead64(P + I - 8);
  end;

  A := A xor Secret[1];
  B := B xor Seed;
  RapidMum(A, B);
  Result := RapidMix(A xor Secret[7], B xor Secret[1] xor I);
end;

function RapidHashMicroInternal(Key: Pointer; Len: SizeUInt; Seed: QWord; const Secret: TRapidSecret): QWord;
var
  P: PByte;
  A, B: QWord;
  I: SizeUInt;
  See1, See2, See3, See4: QWord;
begin
  P := PByte(Key);
  Seed := Seed xor RapidMix(Seed xor Secret[2], Secret[1]);
  A := 0;
  B := 0;
  I := Len;

  if Len <= 16 then
  begin
    if Len >= 4 then
    begin
      Seed := Seed xor Len;
      if Len >= 8 then
      begin
        A := RapidRead64(P);
        B := RapidRead64(P + Len - 8);
      end
      else
      begin
        A := RapidRead32(P);
        B := RapidRead32(P + Len - 4);
      end;
    end
    else if Len > 0 then
    begin
      A := (QWord(P[0]) shl 45) or QWord(P[Len - 1]);
      B := QWord(P[Len shr 1]);
    end;
  end
  else
  begin
    if I > 80 then
    begin
      See1 := Seed;
      See2 := Seed;
      See3 := Seed;
      See4 := Seed;
      repeat
        Seed := RapidMix(RapidRead64(P) xor Secret[0], RapidRead64(P + 8) xor Seed);
        See1 := RapidMix(RapidRead64(P + 16) xor Secret[1], RapidRead64(P + 24) xor See1);
        See2 := RapidMix(RapidRead64(P + 32) xor Secret[2], RapidRead64(P + 40) xor See2);
        See3 := RapidMix(RapidRead64(P + 48) xor Secret[3], RapidRead64(P + 56) xor See3);
        See4 := RapidMix(RapidRead64(P + 64) xor Secret[4], RapidRead64(P + 72) xor See4);
        Inc(P, 80);
        Dec(I, 80);
      until I <= 80;
      Seed := Seed xor See1;
      See2 := See2 xor See3;
      Seed := Seed xor See4;
      Seed := Seed xor See2;
    end;

    if I > 16 then
    begin
      Seed := RapidMix(RapidRead64(P) xor Secret[2], RapidRead64(P + 8) xor Seed);
      if I > 32 then
      begin
        Seed := RapidMix(RapidRead64(P + 16) xor Secret[2], RapidRead64(P + 24) xor Seed);
        if I > 48 then
        begin
          Seed := RapidMix(RapidRead64(P + 32) xor Secret[1], RapidRead64(P + 40) xor Seed);
          if I > 64 then
            Seed := RapidMix(RapidRead64(P + 48) xor Secret[1], RapidRead64(P + 56) xor Seed);
        end;
      end;
    end;

    A := RapidRead64(P + I - 16) xor I;
    B := RapidRead64(P + I - 8);
  end;

  A := A xor Secret[1];
  B := B xor Seed;
  RapidMum(A, B);
  Result := RapidMix(A xor Secret[7], B xor Secret[1] xor I);
end;

function RapidHashNanoInternal(Key: Pointer; Len: SizeUInt; Seed: QWord; const Secret: TRapidSecret): QWord;
var
  P: PByte;
  A, B: QWord;
  I: SizeUInt;
  See1, See2: QWord;
begin
  P := PByte(Key);
  Seed := Seed xor RapidMix(Seed xor Secret[2], Secret[1]);
  A := 0;
  B := 0;
  I := Len;

  if Len <= 16 then
  begin
    if Len >= 4 then
    begin
      Seed := Seed xor Len;
      if Len >= 8 then
      begin
        A := RapidRead64(P);
        B := RapidRead64(P + Len - 8);
      end
      else
      begin
        A := RapidRead32(P);
        B := RapidRead32(P + Len - 4);
      end;
    end
    else if Len > 0 then
    begin
      A := (QWord(P[0]) shl 45) or QWord(P[Len - 1]);
      B := QWord(P[Len shr 1]);
    end;
  end
  else
  begin
    if I > 48 then
    begin
      See1 := Seed;
      See2 := Seed;
      repeat
        Seed := RapidMix(RapidRead64(P) xor Secret[0], RapidRead64(P + 8) xor Seed);
        See1 := RapidMix(RapidRead64(P + 16) xor Secret[1], RapidRead64(P + 24) xor See1);
        See2 := RapidMix(RapidRead64(P + 32) xor Secret[2], RapidRead64(P + 40) xor See2);
        Inc(P, 48);
        Dec(I, 48);
      until I <= 48;
      Seed := Seed xor See1;
      Seed := Seed xor See2;
    end;

    if I > 16 then
    begin
      Seed := RapidMix(RapidRead64(P) xor Secret[2], RapidRead64(P + 8) xor Seed);
      if I > 32 then
        Seed := RapidMix(RapidRead64(P + 16) xor Secret[2], RapidRead64(P + 24) xor Seed);
    end;

    A := RapidRead64(P + I - 16) xor I;
    B := RapidRead64(P + I - 8);
  end;

  A := A xor Secret[1];
  B := B xor Seed;
  RapidMum(A, B);
  Result := RapidMix(A xor Secret[7], B xor Secret[1] xor I);
end;

function RapidHashWithSeed(Key: Pointer; Len: SizeUInt; Seed: QWord): QWord;
begin
  Result := RapidHashInternal(Key, Len, Seed, RapidSecret);
end;

function RapidHash(const S: RawByteString): QWord;
begin
  if Length(S) = 0 then
    Result := RapidHashWithSeed(nil, 0, 0)
  else
    Result := RapidHashWithSeed(Pointer(S), Length(S), 0);
end;

function RapidHash(const Buffer; Len: SizeUInt): QWord;
begin
  Result := RapidHashWithSeed(@Buffer, Len, 0);
end;

function RapidHashMicroWithSeed(Key: Pointer; Len: SizeUInt; Seed: QWord): QWord;
begin
  Result := RapidHashMicroInternal(Key, Len, Seed, RapidSecret);
end;

function RapidHashMicro(const S: RawByteString): QWord;
begin
  if Length(S) = 0 then
    Result := RapidHashMicroWithSeed(nil, 0, 0)
  else
    Result := RapidHashMicroWithSeed(Pointer(S), Length(S), 0);
end;

function RapidHashMicro(const Buffer; Len: SizeUInt): QWord;
begin
  Result := RapidHashMicroWithSeed(@Buffer, Len, 0);
end;

function RapidHashNanoWithSeed(Key: Pointer; Len: SizeUInt; Seed: QWord): QWord;
begin
  Result := RapidHashNanoInternal(Key, Len, Seed, RapidSecret);
end;

function RapidHashNano(const S: RawByteString): QWord;
begin
  if Length(S) = 0 then
    Result := RapidHashNanoWithSeed(nil, 0, 0)
  else
    Result := RapidHashNanoWithSeed(Pointer(S), Length(S), 0);
end;

function RapidHashNano(const Buffer; Len: SizeUInt): QWord;
begin
  Result := RapidHashNanoWithSeed(@Buffer, Len, 0);
end;

end.
