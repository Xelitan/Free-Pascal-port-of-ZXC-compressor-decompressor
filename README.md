# Free Pascal port of ZXC v0.10.0 compressor/decompressor

https://github.com/hellobertrand/zxc
 
# Usage
Add ZxcSimple to your uses

```
function ZxcCompressStreams(InStr, OutStr: TStream): Integer;
function ZxcDecompressStreams(InStr, OutStr: TStream): Integer;

function ZxcCompressFile(const Infilename, Outfilename: String): Integer;
function ZxcDecompressFile(const Infilename, Outfilename: String): Integer;

function Zxc(Uncompressed: AnsiString): AnsiString;
function UnZxc(Compressed: AnsiString): AnsiString;
```
