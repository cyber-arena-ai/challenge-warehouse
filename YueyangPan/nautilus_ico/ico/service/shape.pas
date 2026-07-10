{*************************************************************}
{                                                             }
{             Haiku Vector Image Format Server                }
{                                                             }
{  Copyright (c) 2025 Alexander Taylor <ajtaylor@fuzyll.com>  }
{                                                             }
{        Licensed under the Apache License, Version 2.0       }
{                                                             }
{*************************************************************}

unit IcoShape;

interface

uses
  SysUtils,
  Classes,
  IcoPoint,
  IcoTransformer,
  Generics.Collections;

const
  ShapeHasGlobalTransform = 1 shl 1;
  ShapeIsHinted = 1 shl 2;
  ShapeHasLevelOfDetail = 1 shl 3;
  ShapeHasTransformers = 1 shl 4;
  ShapeIsTranslated = 1 shl 5;

type
  TShapeType = (
    PathSource = 10
  );

  TShape = class
  private
    FHinted: Boolean;
    FMinVisibility, FMaxVisibility: Single;
    FType: TShapeType;
    FStyle: Byte;
    FPaths: TList<Byte>;
    FTransformers: TList;
    function GetPath(const Idx: Cardinal): Byte;
    procedure SetPath(const Idx: Cardinal; Value: Byte);
    function GetTransformer(const Idx: Cardinal): TTransformer;
    procedure SetTransformer(const Idx: Cardinal; Value: TTransformer);
    procedure CheckPaths;
  public
    constructor Create;
    destructor Destroy; override;
    function GetPathCount: Integer;
    procedure AddPath(PathIndex: Byte);
    procedure RemovePath(Idx: Cardinal);
    function GetTransformerCount: Integer;
    procedure AddTransformer(Transformer: TTransformer); overload;
    procedure AddTransformer(Transformer: TTransformer; const Idx: Cardinal); overload;
    procedure RemoveTransformer(const Idx: Cardinal);
    class function FromBytes(const Buffer: TBytes; var Idx: Cardinal): TShape;
    function ToBytes: TBytes;
    property ShapeType: TShapeType read FType write FType;
    property Style: Byte read FStyle write FStyle;
    property Paths[Idx: Cardinal]: Byte read GetPath write SetPath;
    property IsHinted: Boolean read FHinted write FHinted;
    property MinVisibility: Single read FMinVisibility write FMinVisibility;
    property MaxVisibility: Single read FMaxVisibility write FMaxVisibility;
    property Transformers[Idx: Cardinal]: TTransformer read GetTransformer write SetTransformer;
  end;

implementation

{ TShape }

constructor TShape.Create;
begin
  inherited Create;
  FPaths := TList<Byte>.Create;
  FTransformers := TList.Create;
  FHinted := False;
  FMinVisibility := 0.0;
  FMaxVisibility := 4.0;
end;

destructor TShape.Destroy;
var
  i: Integer;
begin
  for i := 0 to FTransformers.Count - 1 do
    TTransformer(FTransformers[i]).Free;
  FTransformers.Free;
  FPaths.Free;
  inherited Destroy;
end;

{ TShape Deserialize }

/// <summary>Deserializes a Shape.</summary>
/// <param name="Buffer">The buffer to deserialize from.</param>
/// <param name="Idx">The index to start deserialization at.</param>
/// <returns>The deserialized Shape.</returns>
/// <exception cref="ERangeError">Thrown if the buffer is too small, contains invalid shape type, or insufficient transformer data.</exception>
class function TShape.FromBytes(const Buffer: TBytes; var Idx: Cardinal): TShape;
var
  NPaths, i, Flag, NTransformers, Min, Max: Byte;
  Transform, LOD, HasTransformer, Translation: Boolean;
  TX, TY: Single;
begin
  Result := TShape.Create;

  // Check buffer bounds for shape type, style, and path count
  if Idx + 2 >= Length(Buffer) then
{$IFDEF DEBUG}
    raise ERangeError.Create('Buffer too small for shape type, style, and path count');
{$ELSE}
    raise ERangeError.Create('Buffer too small');
{$ENDIF}

  // Validate shape type
  if Buffer[Idx] <> 10 then  // TShapeType.PathSource = 10
{$IFDEF DEBUG}
    raise ERangeError.Create('Invalid shape type');
{$ELSE}
    raise ERangeError.Create('Invalid type');
{$ENDIF}

  // Read shape type and style
  Result.ShapeType := TShapeType(Buffer[Idx]);
  Inc(Idx);
  Result.Style := Buffer[Idx];
  Inc(Idx);

  // Read paths
  NPaths := Buffer[Idx];
  Inc(Idx);
  if (NPaths > 0) then
  begin;
    // Check buffer bounds for all path indices
    if Idx + NPaths - 1 >= Length(Buffer) then
{$IFDEF DEBUG}
      raise ERangeError.Create('Buffer too small for path indices');
{$ELSE}
      raise ERangeError.Create('Buffer too small');
{$ENDIF}

    for i := 0 to NPaths - 1 do
    begin
      Result.AddPath(Buffer[Idx]);
      Inc(Idx);
    end;
  end;

  // Check buffer bounds for flags
  if Idx >= Length(Buffer) then
{$IFDEF DEBUG}
    raise ERangeError.Create('Buffer too small for shape flags');
{$ELSE}
    raise ERangeError.Create('Buffer too small');
{$ENDIF}

  // Read flags
  Flag := Buffer[Idx];
  Inc(Idx);
  Transform := (Flag and ShapeHasGlobalTransform) <> 0;
  Result.IsHinted := (Flag and ShapeIsHinted) <> 0;
  LOD := (Flag and ShapeHasLevelOfDetail) <> 0;
  HasTransformer := (Flag and ShapeHasTransformers) <> 0;
  Translation := (Flag and ShapeIsTranslated) <> 0;

  // Read global transform and translate
  if Transform then
  begin
    Result.AddTransformer(TAffineTransformer.FromBytes(Buffer, Idx));
  end
  else if Translation then
  begin
    TX := TPoint.ReadCoordinate(Buffer, Idx);
    TY := TPoint.ReadCoordinate(Buffer, Idx);
    if (TX <> 0.0) or (TY <> 0.0) then
      // Only attempt to translate if it will result in a real value
      Result.AddTransformer(TAffineTransformer.Create(1.0, 1.0, 0.0, 0.0, TX, TY));
  end;

  // Read level of detail
  if LOD then
  begin
    // Check buffer bounds for LOD values
    if Idx + 1 >= Length(Buffer) then
{$IFDEF DEBUG}
      raise ERangeError.Create('Buffer too small for level of detail data');
{$ELSE}
      raise ERangeError.Create('Buffer too small');
{$ENDIF}

    Min := Buffer[Idx];
    Inc(Idx);
    Max := Buffer[Idx];
    Inc(Idx);
    Result.MinVisibility := Min / 63.75;
    Result.MaxVisibility := Max / 63.75;
  end;

  // Read transforms
  if HasTransformer then
  begin
    // Check buffer bounds for transformer count
    if Idx >= Length(Buffer) then
{$IFDEF DEBUG}
      raise ERangeError.Create('Buffer too small for transformer count');
{$ELSE}
      raise ERangeError.Create('Buffer too small');
{$ENDIF}

    NTransformers := Buffer[Idx];
    Inc(Idx);
    for i := 0 to NTransformers - 1 do
      Result.AddTransformer(TTransformer.FromBytes(Buffer, Idx));
  end;
end;

{ TShape Serialize }

/// <summary>Serializes a Shape.</summary>
/// <returns>The serialized bytes.</returns>
function TShape.ToBytes: TBytes;
var
  Flag, i: Byte;
  PackedFirst: Boolean;
  T: TAffineTransformer;
  Transformer: TTransformer;
  TransformerBytes: TBytes;
  Stream: TMemoryStream;
  FlagPos: Int64;
begin
  Stream := TMemoryStream.Create;
  try
    // Write type
    Stream.WriteByte(Byte(FType));

    // Write style
    Stream.WriteByte(FStyle);

    // Write paths
    Stream.WriteByte(FPaths.Count);
    if FPaths.Count > 0 then
    begin;
      for i := 0 to FPaths.Count - 1 do
        Stream.WriteByte(FPaths[i]);
    end;

    // Write empty flag value (we'll set bits as we go)
    Flag := 0;
    FlagPos := Stream.Position;
    Stream.WriteByte(Flag);

    // Try to pack a global transform/translate in less bytes if possible
    PackedFirst := False;
    if (FTransformers.Count >= 1) and (TTransformer(FTransformers[0]) is TAffineTransformer) then
    begin
      T := TAffineTransformer(FTransformers[0]);
      if (T.SX = 1.0) and (T.SY = 1.0) and (T.SHX = 0.0) and (T.SHY = 0.0) then
      begin
        if ((T.TX = 0) and (T.TY = 0)) then
        begin
          // Omit the identity global transform entirely
          PackedFirst := True;
        end
        else if (Abs(T.TX) >= 0.001) or (Abs(T.TY) >= 0.001) then
        begin
          // XXX: Make sure at least one value can be represented with sufficient precision
          //      Avoids bug where both values become 0 and re-saving the file loses the transform
          PackedFirst := True;
          TPoint.WriteCoordinate(Stream, T.TX);
          TPoint.WriteCoordinate(Stream, T.TY);
          Flag := Flag or ShapeIsTranslated;
        end;
      end;

      if not PackedFirst then
      begin
        PackedFirst := True;
        TransformerBytes := T.ToBytes;
        Stream.Write(TransformerBytes[1], Length(TransformerBytes) - 1);
        Flag := Flag or ShapeHasGlobalTransform;
      end;
    end;

    // Write level of detail if not default
    if (FMinVisibility <> 0.0) or (FMaxVisibility <> 4.0) then
    begin
      Stream.WriteByte(Byte(Round(FMinVisibility * 63.75)));
      Stream.WriteByte(Byte(Round(FMaxVisibility * 63.75)));
      Flag := Flag or ShapeHasLevelOfDetail;
    end;

    // Write transforms if we couldn't pack them above
    if (FTransformers.Count > 1) or ((FTransformers.Count = 1) and not PackedFirst) then
    begin
      if not PackedFirst then
        Stream.WriteByte(FTransformers.Count)
      else
        Stream.WriteByte(FTransformers.Count - 1);

      for i := 0 to FTransformers.Count - 1 do
      begin
        if PackedFirst and (i = 0) then
          Continue;
        Transformer := TTransformer(FTransformers[i]);
        TransformerBytes := Transformer.ToBytes;
        Stream.Write(TransformerBytes[0], Length(TransformerBytes));
      end;
      Flag := Flag or ShapeHasTransformers;
    end;

    if FHinted then
      Flag := Flag or ShapeIsHinted;

    // Update the flag value from earlier in the stream
    Stream.Position := FlagPos;
    Stream.WriteByte(Flag);

    // Return our serialized shape
    SetLength(Result, Stream.Size);
    Stream.Position := 0;
    Stream.ReadBuffer(Result[0], Stream.Size);
  finally
    Stream.Free;
  end;
end;

{ TShape Paths }

/// <summary>Gets the number of Paths in this Shape.</summary>
/// <returns>The number of Paths in this Shape.</returns>
function TShape.GetPathCount: Integer;
begin
  Result := FPaths.Count;
end;

/// <summary>Gets the Path at the specified index.</summary>
/// <param name="Idx">Index of the Path to get.</param>
/// <returns>The Path at the specified index.</returns>
/// <exception cref="EArgumentOutOfRangeException">Thrown if the provided index is out of range.</exception>
function TShape.GetPath(const Idx: Cardinal): Byte;
begin
  if Idx >= FPaths.Count then
    raise EArgumentOutOfRangeException.Create('Index out of range');

  Result := FPaths[Idx];
end;

/// <summary>Replaces the Path at the specified index.</summary>
/// <param name="Idx">Index of the Path to replace.</param>
/// <param name="Value">The new Path (index, not object).</param>
/// <exception cref="EArgumentOutOfRangeException">Thrown if the provided index is out of range.</exception>
procedure TShape.SetPath(const Idx: Cardinal; Value: Byte);
begin
  if Idx >= FPaths.Count then
    raise EArgumentOutOfRangeException.Create('Index out of range');

  FPaths[Idx] := Value;
end;

/// <summary>Adds a Path to the Shape.</summary>
/// <param name="PathIndex">Index of the Path to add.</param>
/// <exception cref="EInvalidOp">Thrown if the maximum number of paths has been reached.</exception>
procedure TShape.AddPath(PathIndex: Byte);
const
  MaxPaths = 255;
begin
  if FPaths.Count >= MaxPaths then
{$IFDEF DEBUG}
    raise EInvalidOp.Create('Maximum number of paths reached');
{$ELSE}
    raise EInvalidOp.Create('Maximum reached');
{$ENDIF}
  FPaths.Add(PathIndex);
  CheckPaths;
end;

/// <summary>Removes a Path from the Shape.</summary>
/// <param name="Idx">Index of the Path to remove.</param>
/// <exception cref="EArgumentOutOfRangeException">Thrown if the provided index is out of range.</exception>
procedure TShape.RemovePath(Idx: Cardinal);
begin
  if Idx >= FPaths.Count then
    raise EArgumentOutOfRangeException.Create('Index out of range');

  FPaths.Delete(Idx);
end;

/// TODO
procedure TShape.CheckPaths;
var
  i: Integer;
begin
  FPaths.Sort;
  if FPaths.Count < 2 then Exit; // No duplicates possible
  for i := FPaths.Count - 1 downto 1 do
  begin
    if FPaths[i] = FPaths[i-1] then
      FPaths.Delete(i);
  end;
end;

{ TShape Transformers }

/// <summary>Gets the number of Transformers in this Shape.</summary>
/// <returns>Number of Transformers in this Shape.</returns>
function TShape.GetTransformerCount: Integer;
begin
  Result := FTransformers.Count;
end;

/// <summary>Gets the Transformer at the specified index.</summary>
/// <param name="Idx">Index of the Transformer to get.</param>
/// <returns>Transformer at the specified index.</returns>
/// <exception cref="EArgumentOutOfRangeException">Thrown if the provided index is out of range.</exception>
function TShape.GetTransformer(const Idx: Cardinal): TTransformer;
begin
  if Idx >= FTransformers.Count then
    raise EArgumentOutOfRangeException.Create('Index out of range');

  Result := TTransformer(FTransformers[Idx]);
end;

/// <summary>Replaces the Transformer at the specified index.</summary>
/// <param name="Idx">Index of the Transformer to replace.</param>
/// <param name="Value">Transformer to replace the existing one.</param>
/// <exception cref="EArgumentOutOfRangeException">Thrown if the provided index is out of range.</exception>
procedure TShape.SetTransformer(const Idx: Cardinal; Value: TTransformer);
begin
  if Idx >= FTransformers.Count then
    raise EArgumentOutOfRangeException.Create('Index out of range');

  TTransformer(FTransformers[Idx]).Free;
  FTransformers[Idx] := Value;
end;

/// <summary>Adds a new Transformer to this Shape.</summary>
/// <param name="ATransformer">Transformer to add.</param>
/// <exception cref="EInvalidOp">Thrown if the maximum number of transformers has been reached.</exception>
procedure TShape.AddTransformer(Transformer: TTransformer);
const
  MaxTransformers = 255;
begin
  if FTransformers.Count >= MaxTransformers then
{$IFDEF DEBUG}
    raise EInvalidOp.Create('Maximum number of transformers reached');
{$ELSE}
    raise EInvalidOp.Create('Maximum reached');
{$ENDIF}
  FTransformers.Add(Transformer);
end;

/// <summary>Inserts the Transformer at the specified index into this Shape.</summary>
/// <param name="Transformer">Transformer to insert.</param>
/// <param name="Idx">Index at which to insert the Transformer.</param>
/// <exception cref="EArgumentOutOfRangeException">Thrown if the provided index is out of range.</exception>
procedure TShape.AddTransformer(Transformer: TTransformer; const Idx: Cardinal);
begin
  if Idx > FTransformers.Count then
    raise EArgumentOutOfRangeException.Create('Index out of range');

  FTransformers.Insert(Idx, Transformer);
end;

/// <summary>Removes the Transformer at the specified index from this Shape.</summary>
/// <param name="Idx">Index of the Transformer to remove.</param>
/// <exception cref="EArgumentOutOfRangeException">Thrown if the provided index is out of range.</exception>
procedure TShape.RemoveTransformer(const Idx: Cardinal);
begin
  if Idx >= FTransformers.Count then
    raise EArgumentOutOfRangeException.Create('Index out of range');

  TTransformer(FTransformers[Idx]).Free;
  FTransformers.Delete(Idx);
end;

end.
