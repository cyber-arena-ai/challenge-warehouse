{*************************************************************}
{                                                             }
{             Haiku Vector Image Format Server                }
{                                                             }
{  Copyright (c) 2025 Alexander Taylor <ajtaylor@fuzyll.com>  }
{                                                             }
{        Licensed under the Apache License, Version 2.0       }
{                                                             }
{*************************************************************}

unit IcoPoint;

interface

uses
  SysUtils,
  Classes;

type
  TPoint = class
  public
    X, Y, XIn, YIn, XOut, YOut: Single;
    constructor Create; overload;
    constructor Create(AX, AY: Single); overload;
    constructor Create(AX, AY, AXIn, AYIn, AXOut, AYOut: Single); overload;
    class function FromBytes(const Buffer: TBytes): TPoint; overload;
    class function FromBytes(const Buffer: TBytes; var Idx: Cardinal): TPoint; overload;
    function ToBytes: TBytes;
    class function ReadCoordinate(const Buffer: TBytes; var Idx: Cardinal): Single;
    class procedure WriteCoordinate(var Stream: TMemoryStream; Coordinate: Single);
  end;

implementation

{ TPoint }

constructor TPoint.Create;
begin
  inherited Create;
  X := 0.0;
  Y := 0.0;
  XIn := 0.0;
  YIn := 0.0;
  XOut := 0.0;
  YOut := 0.0;
end;

constructor TPoint.Create(AX, AY: Single);
begin
  inherited Create;
  X := AX;
  Y := AY;
  XIn := AX;
  YIn := AY;
  XOut := AX;
  YOut := AY;
end;

constructor TPoint.Create(AX, AY, AXIn, AYIn, AXOut, AYOut: Single);
begin
  inherited Create;
  X := AX;
  Y := AY;
  XIn := AXIn;
  YIn := AYIn;
  XOut := AXOut;
  YOut := AYOut;
end;

{ TPoint Deserialize }

/// <summary>Deserializes a Point.</summary>
/// <param name="Buffer">The buffer to deserialize from.</param>
/// <returns>The deserialized Point.</returns>
/// <exception cref="ERangeError">Thrown if the buffer is too small for point coordinate data.</exception>
class function TPoint.FromBytes(const Buffer: TBytes): TPoint;
var
  Idx: Cardinal;
begin
  Idx := 0;
  Result := FromBytes(Buffer, Idx);
end;

/// <summary>Deserializes a Point.</summary>
/// <param name="Buffer">The buffer to deserialize from.</param>
/// <param name="Idx">The index to start deserialization at.</param>
/// <returns>The deserialized Point.</returns>
/// <exception cref="ERangeError">Thrown if the buffer is too small for point coordinate data.</exception>
class function TPoint.FromBytes(const Buffer: TBytes; var Idx: Cardinal): TPoint;
begin
  Result := TPoint.Create;
  Result.X := ReadCoordinate(Buffer, Idx);
  Result.Y := ReadCoordinate(Buffer, Idx);
  Result.XIn := ReadCoordinate(Buffer, Idx);
  Result.YIn := ReadCoordinate(Buffer, Idx);
  Result.XOut := ReadCoordinate(Buffer, Idx);
  Result.YOut := ReadCoordinate(Buffer, Idx);
end;

/// <summary>Reads a coordinate from the given buffer.</summary>
/// <param name="Buffer">The buffer to read from.</param>
/// <param name="Idx">The index to start reading at.</param>
/// <returns>The coordinate.</returns>
/// <exception cref="ERangeError">Thrown if the buffer is too small for coordinate data.</exception>
class function TPoint.ReadCoordinate(const Buffer: TBytes; var Idx: Cardinal): Single;
var
  Value: Byte;
  Larger: Word;
begin
  // Check buffer bounds before reading coordinate
  if Idx >= Length(Buffer) then
{$IFDEF DEBUG}
    raise ERangeError.Create('Buffer too small for coordinate data');
{$ELSE}
    raise ERangeError.Create('Buffer too small');
{$ENDIF}

  // Read coordinate
  Value := Buffer[Idx];
  Inc(Idx);

  if (Value and $80) <> 0 then
  begin
    // Handle expanded coordinate
    if Idx >= Length(Buffer) then
{$IFDEF DEBUG}
      raise ERangeError.Create('Buffer too small for expanded coordinate data');
{$ELSE}
      raise ERangeError.Create('Buffer too small');
{$ENDIF}
    Larger := ((Value and $7F) shl 8) or Buffer[Idx];
    Inc(Idx);
    Result := (Larger / 102.0) - 128.0;
  end
  else
  begin
    // Handle simple coordinate
    Result := Value - 32.0;
  end;
end;

{ TPoint Serialize }

/// <summary>Serializes a Point.</summary>
/// <returns>The serialized bytes.</returns>
function TPoint.ToBytes: TBytes;
var
  Stream: TMemoryStream;
begin
  Stream := TMemoryStream.Create;
  try
    WriteCoordinate(Stream, X);
    WriteCoordinate(Stream, Y);
    WriteCoordinate(Stream, XIn);
    WriteCoordinate(Stream, YIn);
    WriteCoordinate(Stream, XOut);
    WriteCoordinate(Stream, YOut);
    SetLength(Result, Stream.Size);
    Stream.Position := 0;
    Stream.ReadBuffer(Result[0], Stream.Size);
  finally
    Stream.Free;
  end;
end;

/// <summary>Writes a coordinate to the given stream.</summary>
/// <param name="Stream">The stream to write to.</param>
/// <param name="Coordinate">The coordinate to write.</param>
class procedure TPoint.WriteCoordinate(var Stream: TMemoryStream; Coordinate: Single);
var
  Shorter: Byte;
  Larger: Word;
  LargerTop, LargerBottom: Byte;
begin
  // Clamp coordinate
  if Coordinate < -128.0 then
    Coordinate := -128.0
  else if Coordinate > 192.0 then
    Coordinate := 192.0;

  // Write coordinate
  if (Trunc(Coordinate * 100.0) = Trunc(Coordinate) * 100) and
     (Coordinate >= -32.0) and (Coordinate <= 95.0) then
  begin
    Shorter := Byte(Trunc(Coordinate + 32.0));
    Stream.WriteBuffer(Shorter, 1);
  end
  else
  begin
    Larger := Word(Round((Coordinate + 128.0) * 102.0));
    Larger := Larger or $8000;
    LargerTop := Byte(Larger shr 8);
    LargerBottom := Byte(Larger);
    Stream.WriteBuffer(LargerTop, 1);
    Stream.WriteBuffer(LargerBottom, 1);
  end;
end;

end.
