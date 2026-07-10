{*************************************************************}
{                                                             }
{             Haiku Vector Image Format Server                }
{                                                             }
{  Copyright (c) 2025 Alexander Taylor <ajtaylor@fuzyll.com>  }
{                                                             }
{        Licensed under the Apache License, Version 2.0       }
{                                                             }
{*************************************************************}

unit IcoTransformer;

interface

uses
  SysUtils,
  Classes;

type
  TTransformerType = (
    Affine = 20,
    Contour = 21,
    Perspective = 22,
    Stroke = 23
  );

  TTransformer = class
  public
    class function ReadValue(const Buffer: TBytes; var Idx: Cardinal): Single;
    class procedure WriteValue(var Stream: TMemoryStream; Value: Single);
    class function FromBytes(const Buffer: TBytes; var Idx: Cardinal): TTransformer;
    function ToBytes: TBytes; virtual; abstract;
  end;

  TAffineTransformer = class(TTransformer)
  public
    SX, SY, SHX, SHY, TX, TY: Single;
    constructor Create; overload;
    constructor Create(ASX, ASY, ASHX, ASHY, ATX, ATY: Single); overload;
    procedure Multiply(const M: TAffineTransformer);
    function Invert: TAffineTransformer;
    procedure TransformPoint(var X, Y: Single);
    class function FromBytes(const Buffer: TBytes; var Idx: Cardinal): TAffineTransformer;
    function ToBytes: TBytes; override;
  end;

  TContourTransformer = class(TTransformer)
  public
    Width: Single;
    LineJoin, MiterLimit: Byte;
    constructor Create; overload;
    constructor Create(AWidth: Single; ALineJoin, AMiterLimit: Byte); overload;
    class function FromBytes(const Buffer: TBytes; var Idx: Cardinal): TContourTransformer;
    function ToBytes: TBytes; override;
  end;

  TPerspectiveTransformer = class(TTransformer)
  public
    SX, SY, SHX, SHY, TX, TY, W0, W1, W2: Single;
    constructor Create; overload;
    constructor Create(ASX, ASY, ASHX, ASHY, ATX, ATY, AW0, AW1, AW2: Single); overload;
    constructor Create(const AT: TAffineTransformer); overload;
    class function FromBytes(const Buffer: TBytes; var Idx: Cardinal): TPerspectiveTransformer;
    function ToBytes: TBytes; override;
  end;

  TLineJoin = (ljMiter, ljRound, ljBevel);
  TLineCap = (lcButt, lcRound, lcSquare);

  TStrokeTransformer = class(TTransformer)
  public
    Width: Single;
    LineJoin: TLineJoin;
    LineCap: TLineCap;
    MiterLimit: Byte;
    constructor Create; overload;
    constructor Create(AWidth: Single; ALineJoin: TLineJoin; ALineCap: TLineCap; AMiterLimit: Byte); overload;
    class function FromBytes(const Buffer: TBytes; var Idx: Cardinal): TStrokeTransformer;
    function ToBytes: TBytes; override;
  end;

implementation

{ TTransformer }

/// <summary>Deserializes a Transformer.</summary>
/// <param name="Buffer">The buffer to deserialize from.</param>
/// <param name="Idx">The index to start deserialization at.</param>
/// <returns>The deserialized Transformer.</returns>
/// <remarks>This method uses the first byte (type) to determine which Transformer object it should create.</remarks>
class function TTransformer.FromBytes(const Buffer: TBytes; var Idx: Cardinal): TTransformer;
var
  TransformerType: TTransformerType;
begin
  TransformerType := TTransformerType(Buffer[Idx]);
  Inc(Idx);
  case TransformerType of
    TTransformerType.Affine: Result := TAffineTransformer.FromBytes(Buffer, Idx);
    TTransformerType.Contour: Result := TContourTransformer.FromBytes(Buffer, Idx);
    TTransformerType.Perspective: Result := TPerspectiveTransformer.FromBytes(Buffer, Idx);
    TTransformerType.Stroke: Result := TStrokeTransformer.FromBytes(Buffer, Idx);
  else
{$IFDEF DEBUG}
    raise ERangeError.Create('Not a valid transformer type');
{$ELSE}
    raise ERangeError.Create('Invalid type');
{$ENDIF}
  end;
end;

/// No ToBytes method is implemented for TTransformer. This is intentional.
/// Serialization must be performed on a specific Transformer object as there is
/// no concept of a 'generic' Transformer in the HVIF format.

/// <summary>Deserializes a floating-point value for a Transformer.</summary>
/// <param name="Buffer">The buffer to deserialize from.</param>
/// <param name="Idx">The index to start deserializing at.</param>
/// <returns>The deserialized floating-point value.</returns>
class function TTransformer.ReadValue(const Buffer: TBytes; var Idx: Cardinal): Single;
var
  Raw: Cardinal;
  Sign, Mant: Cardinal;
  Exp: Integer;
  Value: Cardinal;
begin
  Raw := Buffer[Idx] shl 16 or Buffer[Idx+1] shl 8 or Buffer[Idx+2];
  Inc(Idx, 3);
  if Raw = 0 then
    Result := 0.0
  else
  begin
    Sign := (Raw and $800000) shr 23;
    Exp := ((Raw and $7E0000) shr 17) - 32;
    Mant := Raw and $01FFFF;
    Value := (Sign shl 31) or ((Exp + 127) shl 23) or (Mant shl 6);
    Result := PSingle(@Value)^;
  end;
end;

/// <summary>Serializes a floating-point value for a Transformer.</summary>
/// <param name="Stream">The stream to serialize to.</param>
/// <param name="Value">The floating-point value to serialize.</param>
class procedure TTransformer.WriteValue(var Stream: TMemoryStream; Value: Single);
var
  IntValue: Cardinal;
  Sign, Mant: Cardinal;
  Exp: Integer;
  Raw: Cardinal;
  TmpByte: Byte;
begin
  IntValue := PCardinal(@Value)^;
  Sign := (IntValue and $80000000) shr 31;
  Exp := ((IntValue and $7F800000) shr 23) - 127;
  Mant := IntValue and $007FFFFF;

  if (Exp < -32) or (Exp >= 32) then
  begin
    TmpByte := 0;
    Stream.WriteBuffer(TmpByte, 1);
    Stream.WriteBuffer(TmpByte, 1);
    Stream.WriteBuffer(TmpByte, 1);
  end
  else
  begin
    Raw := (Sign shl 23) or ((Exp + 32) shl 17) or (Mant shr 6);
    TmpByte := Byte(Raw shr 16);
    Stream.WriteBuffer(TmpByte, 1);
    TmpByte := Byte(Raw shr 8);
    Stream.WriteBuffer(TmpByte, 1);
    TmpByte := Byte(Raw);
    Stream.WriteBuffer(TmpByte, 1);
  end;
end;

{ TAffineTransformer }

constructor TAffineTransformer.Create;
begin
  inherited Create;
  SX := 1.0;
  SY := 1.0;
  SHX := 0.0;
  SHY := 0.0;
  TX := 0.0;
  TY := 0.0;
end;

constructor TAffineTransformer.Create(ASX, ASY, ASHX, ASHY, ATX, ATY: Single);
begin
  inherited Create;
  SX := ASX;
  SY := ASY;
  SHX := ASHX;
  SHY := ASHY;
  TX := ATX;
  TY := ATY;
end;

/// <summary>Deserializes an Affine Transformer.</summary>
/// <param name="Buffer">The buffer to deserialize from.</param>
/// <param name="Idx">The index to start deserialization at.</param>
/// <returns>The deserialized Affine Transformer.</returns>
/// <remarks>This method assumes you have already advanced past the type identifier. If you need type detection, use the base TTransformer class.</remarks>
class function TAffineTransformer.FromBytes(const Buffer: TBytes; var Idx: Cardinal): TAffineTransformer;
var
  SX, SY, SHX, SHY, TX, TY: Single;
begin
  SX := TTransformer.ReadValue(Buffer, Idx);
  SHY := TTransformer.ReadValue(Buffer, Idx);
  SHX := TTransformer.ReadValue(Buffer, Idx);
  SY := TTransformer.ReadValue(Buffer, Idx);
  TX := TTransformer.ReadValue(Buffer, Idx);
  TY := TTransformer.ReadValue(Buffer, Idx);
  Result := TAffineTransformer.Create(SX, SY, SHX, SHY, TX, TY);
end;

/// <summary>Serializes an Affine Transformer.</summary>
/// <returns>The serialized bytes.</returns>
function TAffineTransformer.ToBytes: TBytes;
var
  Stream: TMemoryStream;
begin
  Stream := TMemoryStream.Create;
  try
    Stream.WriteByte(Byte(TTransformerType.Affine));
    TTransformer.WriteValue(Stream, SX);
    TTransformer.WriteValue(Stream, SHY);
    TTransformer.WriteValue(Stream, SHX);
    TTransformer.WriteValue(Stream, SY);
    TTransformer.WriteValue(Stream, TX);
    TTransformer.WriteValue(Stream, TY);
    SetLength(Result, Stream.Size);
    Stream.Position := 0;
    Stream.ReadBuffer(Result[0], Stream.Size);
  finally
    Stream.Free;
  end;
end;

/// TODO
procedure TAffineTransformer.Multiply(const M: TAffineTransformer);
var
  NewSX, NewSY, NewSHX, NewSHY, NewTX, NewTY: Single;
begin
  NewSX := SX * M.SX + SHY * M.SHX;
  NewSY := SY * M.SY + SHX * M.SHY;
  NewSHX := SHX * M.SX + SY * M.SHX;
  NewSHY := SHY * M.SY + SX * M.SHY;
  NewTX := TX * M.SX + TY * M.SHX + M.TX;
  NewTY := TY * M.SY + TX * M.SHY + M.TY;
  SX := NewSX;
  SY := NewSY;
  SHX := NewSHX;
  SHY := NewSHY;
  TX := NewTX;
  TY := NewTY;
end;

/// TODO
function TAffineTransformer.Invert: TAffineTransformer;
var
  Det: Single;
begin
  Result := TAffineTransformer.Create;
  Det := SX * SY - SHX * SHY;
  if Det = 0 then Exit; // Not invertible

  Result.SX := SY / Det;
  Result.SHX := -SHX / Det;
  Result.SHY := -SHY / Det;
  Result.SY := SX / Det;
  Result.TX := (SHX * TY - SY * TX) / Det;
  Result.TY := (SHY * TX - SX * TY) / Det;
end;

/// TODO
procedure TAffineTransformer.TransformPoint(var X, Y: Single);
var
  NewX, NewY: Single;
begin
  NewX := X * SX + Y * SHX + TX;
  NewY := X * SHY + Y * SY + TY;
  X := NewX;
  Y := NewY;
end;

{ TContourTransformer }

constructor TContourTransformer.Create;
begin
  inherited Create;
  Width := 0.0;
  LineJoin := 0;
  MiterLimit := 0;
end;

constructor TContourTransformer.Create(AWidth: Single; ALineJoin, AMiterLimit: Byte);
begin
  inherited Create;
  Width := AWidth;
  LineJoin := ALineJoin;
  MiterLimit := AMiterLimit;
end;

/// <summary>Deserializes a Contour Transformer.</summary>
/// <param name="Buffer">The buffer to deserialize from.</param>
/// <param name="Idx">The index to start deserialization at.</param>
/// <returns>The deserialized Contour Transformer.</returns>
/// <remarks>This method assumes you have already advanced past the type identifier. If you need type detection, use the base TTransformer class.</remarks>
class function TContourTransformer.FromBytes(const Buffer: TBytes; var Idx: Cardinal): TContourTransformer;
var
  Width: Single;
  LineJoin, MiterLimit: Byte;
begin
  Width := Buffer[Idx] - 128.0;
  Inc(Idx);
  LineJoin := Buffer[Idx];
  Inc(Idx);
  MiterLimit := Buffer[Idx];
  Inc(Idx);
  Result := TContourTransformer.Create(Width, LineJoin, MiterLimit);
end;

/// <summary>Serializes a Contour Transformer.</summary>
/// <returns>The serialized bytes.</returns>
function TContourTransformer.ToBytes: TBytes;
var
  Stream: TMemoryStream;
begin
  Stream := TMemoryStream.Create;
  try
    Stream.WriteByte(Byte(TTransformerType.Contour));
    Stream.WriteByte(Byte(Round(Width + 128.0)));
    Stream.WriteByte(LineJoin);
    Stream.WriteByte(MiterLimit);
    SetLength(Result, Stream.Size);
    Stream.Position := 0;
    Stream.ReadBuffer(Result[0], Stream.Size);
  finally
    Stream.Free;
  end;
end;

{ TPerspectiveTransformer }

constructor TPerspectiveTransformer.Create;
begin
  inherited Create;
  SX := 1.0;
  SY := 1.0;
  SHX := 0.0;
  SHY := 0.0;
  TX := 0.0;
  TY := 0.0;
  W0 := 0.0;
  W1 := 0.0;
  W2 := 1.0;
end;

constructor TPerspectiveTransformer.Create(const AT: TAffineTransformer);
begin
  inherited Create;
  SX := AT.SX;
  SY := AT.SY;
  SHX := AT.SHX;
  SHY := AT.SHY;
  TX := AT.TX;
  TY := AT.TY;
  W0 := 0.0;
  W1 := 0.0;
  W2 := 1.0;
end;

constructor TPerspectiveTransformer.Create(ASX, ASY, ASHX, ASHY, ATX, ATY, AW0, AW1, AW2: Single);
begin
  inherited Create;
  SX := ASX;
  SY := ASY;
  SHX := ASHX;
  SHY := ASHY;
  TX := ATX;
  TY := ATY;
  W0 := AW0;
  W1 := AW1;
  W2 := AW2;
end;

/// <summary>Deserializes a Perspective Transformer.</summary>
/// <param name="Buffer">The buffer to deserialize from.</param>
/// <param name="Idx">The index to start deserialization at.</param>
/// <returns>The deserialized Perspective Transformer.</returns>
/// <remarks>This method assumes you have already advanced past the type identifier. If you need type detection, use the base TTransformer class.</remarks>
class function TPerspectiveTransformer.FromBytes(const Buffer: TBytes; var Idx: Cardinal): TPerspectiveTransformer;
var
  SX, SY, SHX, SHY, TX, TY, W0, W1, W2: Single;
begin
  SX := TTransformer.ReadValue(Buffer, Idx);
  SHY := TTransformer.ReadValue(Buffer, Idx);
  W0 := TTransformer.ReadValue(Buffer, Idx);
  SHX := TTransformer.ReadValue(Buffer, Idx);
  SY := TTransformer.ReadValue(Buffer, Idx);
  W1 := TTransformer.ReadValue(Buffer, Idx);
  TX := TTransformer.ReadValue(Buffer, Idx);
  TY := TTransformer.ReadValue(Buffer, Idx);
  W2 := TTransformer.ReadValue(Buffer, Idx);
  Result := TPerspectiveTransformer.Create(SX, SY, SHX, SHY, TX, TY, W0, W1, W2);
end;

/// <summary>Serializes a Perspective Transformer.</summary>
/// <returns>The serialized bytes.</returns>
function TPerspectiveTransformer.ToBytes: TBytes;
var
  Stream: TMemoryStream;
begin
  Stream := TMemoryStream.Create;
  try
    Stream.WriteByte(Byte(TTransformerType.Perspective));
    TTransformer.WriteValue(Stream, SX);
    TTransformer.WriteValue(Stream, SHY);
    TTransformer.WriteValue(Stream, W0);
    TTransformer.WriteValue(Stream, SHX);
    TTransformer.WriteValue(Stream, SY);
    TTransformer.WriteValue(Stream, W1);
    TTransformer.WriteValue(Stream, TX);
    TTransformer.WriteValue(Stream, TY);
    TTransformer.WriteValue(Stream, W2);
    SetLength(Result, Stream.Size);
    Stream.Position := 0;
    Stream.ReadBuffer(Result[0], Stream.Size);
  finally
    Stream.Free;
  end;
end;

{ TStrokeTransformer }

constructor TStrokeTransformer.Create;
begin
  inherited Create;
  Width := 0.0;
  LineJoin := TLineJoin.ljMiter;
  LineCap := TLineCap.lcButt;
  MiterLimit := 4;
end;

constructor TStrokeTransformer.Create(AWidth: Single; ALineJoin: TLineJoin; ALineCap: TLineCap; AMiterLimit: Byte);
begin
  inherited Create;
  Width := AWidth;
  LineJoin := ALineJoin;
  LineCap := ALineCap;
  MiterLimit := AMiterLimit;
end;

/// <summary>Deserializes a Stroke Transformer.</summary>
/// <param name="Buffer">The buffer to deserialize from.</param>
/// <param name="Idx">The index to start deserialization at.</param>
/// <returns>The deserialized Stroke Transformer.</returns>
/// <remarks>This method assumes you have already advanced past the type identifier. If you need type detection, use the base TTransformer class.</remarks>
class function TStrokeTransformer.FromBytes(const Buffer: TBytes; var Idx: Cardinal): TStrokeTransformer;
var
  Width: Single;
  LineOptions, MiterLimit: Byte;
  LineJoin: TLineJoin;
  LineCap: TLineCap;
begin
  Width := Buffer[Idx] - 128.0;
  Inc(Idx);
  LineOptions := Buffer[Idx];
  Inc(Idx);
  LineJoin := TLineJoin(LineOptions and $F);
  LineCap := TLineCap(LineOptions shr 4);
  MiterLimit := Buffer[Idx];
  Inc(Idx);
  Result := TStrokeTransformer.Create(Width, LineJoin, LineCap, MiterLimit);
end;

/// <summary>Serializes a Stroke Transformer.</summary>
/// <returns>The serialized bytes.</returns>
function TStrokeTransformer.ToBytes: TBytes;
var
  Stream: TMemoryStream;
begin
  Stream := TMemoryStream.Create;
  try
    Stream.WriteByte(Byte(TTransformerType.Stroke));
    Stream.WriteByte(Byte(Round(Width + 128.0)));
    Stream.WriteByte((Byte(LineCap) shl 4) or (Byte(LineJoin) and $F));
    Stream.WriteByte(MiterLimit);
    SetLength(Result, Stream.Size);
    Stream.Position := 0;
    Stream.ReadBuffer(Result[0], Stream.Size);
  finally
    Stream.Free;
  end;
end;

end.
