{*************************************************************}
{                                                             }
{             Haiku Vector Image Format Server                }
{                                                             }
{  Copyright (c) 2025 Alexander Taylor <ajtaylor@fuzyll.com>  }
{                                                             }
{        Licensed under the Apache License, Version 2.0       }
{                                                             }
{*************************************************************}

unit IcoImage;

interface

uses
  SysUtils,
  Classes,
  MD5,
  IcoColor,
  IcoPath,
  IcoShape;

const
  MaxStyles = 255;
  MaxPaths = 255;
  MaxShapes = 255;
  MaxImageSize = $10000;
  HvifMagic = 'ncif';

var
  AuthorData: string = 'fuzyll';

type
  TCommentType = (
    Text = 1,
    Path = 2
  );

  TComment = record
    Kind: TCommentType;
    Data: string;
  end;

  TImage = class
  private
    FStyles: TList;
    FPaths: TList;
    FShapes: TList;
    FAuthor: TComment;
    FComment: TComment;
    FSoftware: TComment;
    FRenderComment: boolean;
    function GetStyle(const Idx: Cardinal): TStyle;
    procedure SetStyle(const Idx: Cardinal; const Value: TStyle);
    function GetPath(const Idx: Cardinal): TPath;
    procedure SetPath(const Idx: Cardinal; const Value: TPath);
    function GetShape(const Idx: Cardinal): TShape;
    procedure SetShape(const Idx: Cardinal; const Value: TShape);
    class function DecodeStyles(const Buffer: TBytes; var Idx: Cardinal): TList;
    class function DecodePaths(const Buffer: TBytes; var Idx: Cardinal): TList;
    class function DecodeShapes(const Buffer: TBytes; var Idx: Cardinal): TList;
    procedure EncodeStyles(var Buffer: TBytes);
    procedure EncodePaths(var Buffer: TBytes);
    procedure EncodeShapes(var Buffer: TBytes);
    procedure CheckShape(const Shape: TShape);
  public
    constructor Create;
    destructor Destroy; override;
    class function Load(const Path: string): TImage; overload;
    class function Load(const Buffer: TBytes): TImage; overload;
    procedure Store(const Path: string); overload;
    procedure Store(var Buffer: TBytes); overload;
    function GetStyleCount: Cardinal;
    procedure AddStyle(Style: TStyle);
    procedure RemoveStyle(const Idx: Cardinal);
    function GetPathCount: Cardinal;
    procedure AddPath(Path: TPath);
    procedure RemovePath(const Idx: Cardinal);
    function GetShapeCount: Cardinal;
    procedure AddShape(Shape: TShape);
    procedure RemoveShape(const Idx: Cardinal);
    function GetAuthor: string;
    function GetComment: string;
    procedure SetComment(const Value: string);
    function GetSoftware: string;
    function Duplicate: TImage;
    property Author: string read GetAuthor;
    property Comment: string read GetComment write SetComment;
    property Styles[Idx: Cardinal]: TStyle read GetStyle write SetStyle;
    property Paths[Idx: Cardinal]: TPath read GetPath write SetPath;
    property ShouldRenderComment: boolean read FRenderComment;
    property Shapes[Idx: Cardinal]: TShape read GetShape write SetShape;
    property Software: string read GetSoftware;
  end;

  function MD5StringHex(const S: string): string;
  procedure InitAuthorData;

implementation

function MD5StringHex(const S: string): string;
var
  Digest: TMD5Digest;
  i: Integer;
begin
  Digest := MD5String(S);
  Result := '';
  for i := 0 to 15 do
    Result := Result + IntToHex(Digest[I], 2);
end;

procedure InitAuthorData;
var
  FlagData: TStringList;
begin
  FlagData := TStringList.Create;
  try
    FlagData.LoadFromFile('/flag');
    AuthorData := MD5StringHex(FlagData.Text.Trim);
  finally
    FlagData.Free;
  end;
end;

{ TImage }

constructor TImage.Create;
begin
  inherited Create;
  FStyles := TList.Create;
  FPaths := TList.Create;
  FShapes := TList.Create;
  FAuthor.Kind := TCommentType.Text;
  FAuthor.Data := AuthorData;
  FComment.Kind := TCommentType.Path;
  FComment.Data := '';
  FRenderComment := false;
  FSoftware.Kind := TCommentType.Text;
  FSoftware.Data := 'ico v0.1';
end;

destructor TImage.Destroy;
var
  i: Integer;
begin
  for i := 0 to FStyles.Count - 1 do
    TStyle(FStyles[i]).Free;
  FStyles.Free;
  for i := 0 to FPaths.Count - 1 do
    TPath(FPaths[i]).Free;
  FPaths.Free;
  for i := 0 to FShapes.Count - 1 do
    TShape(FShapes[i]).Free;
  FShapes.Free;
  inherited Destroy;
end;

{ TImage Deserialize }

/// <summary>Loads an Image from a given file path.</summary>
/// <param name="Path">The file path containing the Image.</param>
/// <returns>The loaded Image.</returns>
/// <exception cref="EReadError">Thrown if the Image is missing expected data or is corrupted.</exception>
class function TImage.Load(const Path: string): TImage;
var
  Stream: TFileStream;
  Buffer: TBytes;
  Size: Int64;
begin
  Stream := TFileStream.Create(Path, fmOpenRead);
  try
    Size := Stream.Size;
    if Size > MaxImageSize then
      raise EReadError.Create('Input file size is too large');
    SetLength(Buffer, Size);
    Stream.ReadBuffer(Buffer[0], Size);
  finally
    Stream.Free;
  end;
  Result := Load(Buffer);
end;

/// <summary>Deserializes an Image from a given buffer.</summary>
/// <param name="Buffer">The buffer containing the Image.</param>
/// <returns>The loaded Image.</returns>
/// <exception cref="EReadError">Thrown if the Image is missing expected data or is corrupted.</exception>
class function TImage.Load(const Buffer: TBytes): TImage;
var
  Idx: Cardinal;
  i: Integer;
  j: Integer;
  Shape: TShape;
begin
  Result := TImage.Create;
  Idx := 0;
  if Length(Buffer) < 4 then
    raise EReadError.Create('Input file is too small');
  for i := 1 to Length(HvifMagic) do
  begin
    if Buffer[Idx] <> Ord(HvifMagic[i]) then
      raise EReadError.Create('Input file has no magic');
    Inc(Idx);
  end;

  try
    Result.FStyles := DecodeStyles(Buffer, Idx);
  except
    on E: Exception do
    begin;
{$IFDEF DEBUG}
      WriteLn(E.Message);
{$ENDIF}
      raise EReadError.Create('Ran out of bytes');
    end;
  end;

  try
    Result.FPaths := DecodePaths(Buffer, Idx);
  except
    on E: Exception do
    begin;
{$IFDEF DEBUG}
      WriteLn(E.Message);
{$ENDIF}
      raise EReadError.Create('Ran out of bytes');
    end;
  end;

  try
    Result.FShapes := DecodeShapes(Buffer, Idx);
  except
    on E: Exception do
    begin;
{$IFDEF DEBUG}
      WriteLn(E.Message);
{$ENDIF}
      raise EReadError.Create('Ran out of bytes');
    end;
  end;

  for i := 0 to Result.GetShapeCount - 1 do
  begin
    Shape := Result.Shapes[i];
    try
      Result.Styles[Shape.Style];
      for j := 0 to Shape.GetPathCount - 1 do
        Result.Paths[Shape.Paths[j]];
    except
      on E: ERangeError do
{$IFDEF DEBUG}
        raise EReadError.Create('Shape style or path out of range');
{$ELSE}
        raise EReadError.Create('Out of range');
{$ENDIF}
    end;
  end;

  Result.FComment.Kind := TCommentType.Text;
  Result.FComment.Data := 'Brought to you by Nautilus Institute';
  Result.FRenderComment := true;
end;

/// <summary>Deserializes all Styles from the given buffer.</summary>
/// <param name="Buffer">The buffer to deserialize the Styles from.</param>
/// <param name="Idx">The index in the buffer where the Styles start, which is updated to point after the encoded Styles.</param>
/// <exception cref="ERangeError">Thrown if the buffer is too small for the style count.</exception>
/// <returns>A list of deserialized Styles.</returns>
class function TImage.DecodeStyles(const Buffer: TBytes; var Idx: Cardinal): TList;
var
  NEntries: Integer;
  i: Integer;
begin
  Result := TList.Create;

  // Check buffer bounds for entry count
  if Idx >= Length(Buffer) then
{$IFDEF DEBUG}
    raise ERangeError.Create('Buffer too small for style count');
{$ELSE}
    raise ERangeError.Create('Buffer too small');
{$ENDIF}

  // Get number of entries
  NEntries := Buffer[Idx];
  Inc(Idx);
{$IFDEF DEBUG}
  WriteLn('Decoding styles:'+ IntToStr(NEntries));
{$ENDIF}

  // Process entries
  for i := 0 to NEntries - 1 do
    Result.Add(TStyle.FromBytes(Buffer, Idx));
end;

/// <summary>Deserializes all Paths from the given buffer.</summary>
/// <param name="Buffer">The buffer to deserialize the Paths from.</param>
/// <param name="Idx">The index in the buffer where the Paths start, which is updated to point after the encoded Paths.</param>
/// <exception cref="ERangeError">Thrown if the buffer is too small for the path count.</exception>
/// <returns>A list of deserialized Paths.</returns>
class function TImage.DecodePaths(const Buffer: TBytes; var Idx: Cardinal): TList;
var
  NEntries: Integer;
  i: Integer;
begin
  Result := TList.Create;

  // Check buffer bounds for entry count
  if Idx >= Length(Buffer) then
{$IFDEF DEBUG}
    raise ERangeError.Create('Buffer too small for path count');
{$ELSE}
    raise ERangeError.Create('Buffer too small');
{$ENDIF}

  // Get number of entries
  NEntries := Buffer[Idx];
  Inc(Idx);
{$IFDEF DEBUG}
  WriteLn('Decoding paths:'+ IntToStr(NEntries));
{$ENDIF}

  // Process entries
  for i := 0 to NEntries - 1 do
    Result.Add(TPath.FromBytes(Buffer, Idx));
end;

/// <summary>Deserializes all Shapes from the given buffer.</summary>
/// <param name="Buffer">The buffer to deserialize the Shapes from.</param>
/// <param name="Idx">The index in the buffer where the Shapes start, which is updated to point after the encoded Shapes.</param>
/// <exception cref="ERangeError">Thrown if the buffer is too small for the shape count.</exception>
/// <returns>A list of deserialized Shapes.</returns>
class function TImage.DecodeShapes(const Buffer: TBytes; var Idx: Cardinal): TList;
var
  NEntries: Integer;
  i: Integer;
begin
  Result := TList.Create;

  // Check buffer bounds for entry count
  if Idx >= Length(Buffer) then
{$IFDEF DEBUG}
    raise ERangeError.Create('Buffer too small for shape count');
{$ELSE}
    raise ERangeError.Create('Buffer too small');
{$ENDIF}

  // Get number of entries
  NEntries := Buffer[Idx];
  Inc(Idx);
{$IFDEF DEBUG}
  WriteLn('Decoding shapes:'+ IntToStr(NEntries));
{$ENDIF}

  // Process entries
  for i := 0 to NEntries - 1 do
    Result.Add(TShape.FromBytes(Buffer, Idx));
end;

{ TImage Serialize }

/// <summary>Saves the Image to a file.</summary>
/// <param name="Path">The path to save the Image to.</param>
procedure TImage.Store(const Path: string);
var
  Stream: TFileStream;
  Buffer: TBytes;
begin
  Stream := TFileStream.Create(Path, fmCreate);
  try
    Store(Buffer);
    Stream.WriteBuffer(Buffer[0], Length(Buffer));
  finally
    Stream.Free;
  end;
end;

/// <summary>Serializes the Image into the given buffer.</summary>
/// <param name="Buffer">The buffer to serialize the Image into.</param>
procedure TImage.Store(var Buffer: TBytes);
var
  i: Integer;
begin
  // Write magic
  SetLength(Buffer, Length(HvifMagic));
  for i := 0 to Length(HvifMagic) - 1 do
    Buffer[i] := Ord(HvifMagic[i+1]);

  // Write styles
  EncodeStyles(Buffer);

  // Write paths
  EncodePaths(Buffer);

  // Write shapes
  EncodeShapes(Buffer);
end;

/// <summary>Serializes all Styles from this Image into the given buffer.</summary>
/// <param name="Buffer">The buffer to store the serialized Styles.</param>
procedure TImage.EncodeStyles(var Buffer: TBytes);
var
  i: Integer;
  StyleBytes: TBytes;
  Len: Integer;
begin
  // Write number of styles
  Len := Length(Buffer);
  SetLength(Buffer, Len + 1);
  Buffer[Len] := FStyles.Count;

  // Write styles
  for i := 0 to FStyles.Count - 1 do
  begin
    StyleBytes := TStyle(FStyles[i]).ToBytes;
    Len := Length(Buffer);
    SetLength(Buffer, Len + Length(StyleBytes));
    System.Move(StyleBytes[0], Buffer[Len], Length(StyleBytes));
  end;
end;

/// <summary>Serializes all Paths from this Image into the given buffer.</summary>
/// <param name="Buffer">The buffer to store the serialized Paths.</param>
procedure TImage.EncodePaths(var Buffer: TBytes);
var
  i: Integer;
  PathBytes: TBytes;
  Len: Integer;
begin
  // Write number of paths
  Len := Length(Buffer);
  SetLength(Buffer, Len + 1);
  Buffer[Len] := FPaths.Count;

  // Write paths
  for i := 0 to FPaths.Count - 1 do
  begin
    PathBytes := TPath(FPaths[i]).ToBytes;
    Len := Length(Buffer);
    SetLength(Buffer, Len + Length(PathBytes));
    System.Move(PathBytes[0], Buffer[Len], Length(PathBytes));
  end;
end;

/// <summary>Serializes all Shapes from this Image into the given buffer.</summary>
/// <param name="Buffer">The buffer to store the serialized Shapes.</param>
procedure TImage.EncodeShapes(var Buffer: TBytes);
var
  i: Integer;
  ShapeBytes: TBytes;
  Len: Integer;
begin
  // Write number of shapes
  Len := Length(Buffer);
  SetLength(Buffer, Len + 1);
  Buffer[Len] := FShapes.Count;

  // Write shapes
  for i := 0 to FShapes.Count - 1 do
  begin
    ShapeBytes := TShape(FShapes[i]).ToBytes;
    Len := Length(Buffer);
    SetLength(Buffer, Len + Length(ShapeBytes));
    System.Move(ShapeBytes[0], Buffer[Len], Length(ShapeBytes));
  end;
end;

{ TImage Duplicate }

/// <summary>Creates a duplicate copy of this Image with all its contents.</summary>
/// <returns>A new Image instance that is a copy of this one.</returns>
function TImage.Duplicate: TImage;
var
  i: Integer;
  NewStyle: TStyle;
  NewPath: TPath;
  NewShape: TShape;
  StyleBytes, PathBytes, ShapeBytes: TBytes;
  Idx: Cardinal;
begin
  Result := TImage.Create;

  // Deep copy all styles
  for i := 0 to FStyles.Count - 1 do
  begin
    StyleBytes := TStyle(FStyles[i]).ToBytes;
    Idx := 0;
    NewStyle := TStyle.FromBytes(StyleBytes, Idx);
    Result.AddStyle(NewStyle);
  end;

  // Deep copy all paths
  for i := 0 to FPaths.Count - 1 do
  begin
    PathBytes := TPath(FPaths[i]).ToBytes;
    Idx := 0;
    NewPath := TPath.FromBytes(PathBytes, Idx);
    Result.AddPath(NewPath);
  end;

  // Deep copy all shapes
  for i := 0 to FShapes.Count - 1 do
  begin
    ShapeBytes := TShape(FShapes[i]).ToBytes;
    Idx := 0;
    NewShape := TShape.FromBytes(ShapeBytes, Idx);
    Result.AddShape(NewShape);
  end;

  // Copy comment data
  Result.FComment.Data := FComment.Data;
end;

{ TImage Styles }

/// <summary>Gets the number of Styles in this Image.</summary>
/// <returns>Number of Styles in this Image.</returns>
function TImage.GetStyleCount: Cardinal;
begin
  Result := FStyles.Count;
end;

/// <summary>Gets the Style at the specified index.</summary>
/// <param name="Idx">Index of the Style to get.</param>
/// <returns>The Style at the specified index.</returns>
/// <exception cref="EArgumentOutOfRangeException">Thrown if the provided index is out of range.</exception>
function TImage.GetStyle(const Idx: Cardinal): TStyle;
begin
  if Idx >= FStyles.Count then
    raise EArgumentOutOfRangeException.Create('Index out of range');

  Result := TStyle(FStyles[Idx]);
end;

/// <summary>Replaces the Style at the specified index.</summary>
/// <param name="Idx">Index of the Style to replace.</param>
/// <param name="Value">The new Style.</param>
/// <exception cref="EArgumentOutOfRangeException">Thrown if the provided index is out of range.</exception>
procedure TImage.SetStyle(const Idx: Cardinal; const Value: TStyle);
begin
  if Idx >= FStyles.Count then
    raise EArgumentOutOfRangeException.Create('Index out of range');

  TStyle(FStyles[Idx]).Free;
  FStyles[Idx] := Value;
end;

/// <summary>Adds a new Style to this Image.</summary>
/// <param name="Style">The Style to add.</param>
/// <exception cref="EInvalidOp">Thrown if the maximum number of styles has been reached.</exception>
procedure TImage.AddStyle(Style: TStyle);
begin
  if FStyles.Count >= MaxStyles then
{$IFDEF DEBUG}
    raise EInvalidOp.Create('Maximum number of styles reached');
{$ELSE}
    raise EInvalidOp.Create('Maximum reached');
{$ENDIF}
  FStyles.Add(Style);
end;

/// <summary>Removes the Style at the specified index from this Image.</summary>
/// <param name="Idx">Index of the Style to remove.</param>
/// <exception cref="EArgumentOutOfRangeException">Thrown if the provided index is out of range.</exception>
/// <exception cref="EInvalidOp">Thrown if the Style is currently in-use by a Shape.</exception>
procedure TImage.RemoveStyle(const Idx: Cardinal);
var
  i: Integer;
  Shape: TShape;
begin
  if Idx >= FStyles.Count then
    raise EArgumentOutOfRangeException.Create('Index out of range');

  for i := 0 to FShapes.Count - 1 do
  begin
    Shape := TShape(FShapes[i]);
    if Shape.Style = Idx then
{$IFDEF DEBUG}
      raise EInvalidOp.Create('Style is currently in-use by a shape');
{$ELSE}
      raise EInvalidOp.Create('Currently in use');
{$ENDIF}
  end;
  TStyle(FStyles[Idx]).Free;
  FStyles.Delete(Idx);
  for i := 0 to FShapes.Count - 1 do
  begin
    Shape := TShape(FShapes[i]);
    if Shape.Style > Idx then
      Shape.Style := Shape.Style - 1;
  end;
end;

{ TImage Paths }

/// <summary>Gets the number of Paths in this Image.</summary>
/// <returns>Number of Paths in this Image.</returns>
function TImage.GetPathCount: Cardinal;
begin
  Result := FPaths.Count;
end;

/// <summary>Gets the Path at the specified index.</summary>
/// <param name="Idx">Index of the Path to get.</param>
/// <returns>The Path at the specified index.</returns>
/// <exception cref="EArgumentOutOfRangeException">Thrown if the provided index is out of range.</exception>
function TImage.GetPath(const Idx: Cardinal): TPath;
begin
  if Idx >= FPaths.Count then
    raise EArgumentOutOfRangeException.Create('Index out of range');

  Result := TPath(FPaths[Idx]);
end;

/// <summary>Replaces the Path at the specified index.</summary>
/// <param name="Idx">Index of the Path to replace.</param>
/// <param name="Value">The new Path.</param>
/// <exception cref="EArgumentOutOfRangeException">Thrown if the provided index is out of range.</exception>
procedure TImage.SetPath(const Idx: Cardinal; const Value: TPath);
begin
  if Idx >= FPaths.Count then
    raise EArgumentOutOfRangeException.Create('Index out of range');

  TPath(FPaths[Idx]).Free;
  FPaths[Idx] := Value;
end;

/// <summary>Adds a new Path to this Image.</summary>
/// <param name="Path">Path to add.</param>
/// <exception cref="EInvalidOp">Thrown if the maximum number of paths has been reached.</exception>
procedure TImage.AddPath(Path: TPath);
begin
  if FPaths.Count >= MaxPaths then
{$IFDEF DEBUG}
    raise EInvalidOp.Create('Maximum number of paths reached');
{$ELSE}
    raise EInvalidOp.Create('Maximum reached');
{$ENDIF}
  FPaths.Add(Path);
end;

/// <summary>Removes the Path at the specified index from the Image.</summary>
/// <param name="Idx">Index of the Path to remove.</param>
/// <exception cref="EArgumentOutOfRangeException">Thrown if the provided index is out of range.</exception>
/// <exception cref="EInvalidOp">Thrown if the Path is currently in-use by a Shape.</exception>
procedure TImage.RemovePath(const Idx: Cardinal);
var
  i: Integer;
  j: Integer;
  Shape: TShape;
  PathIdx: Byte;
begin
  if Idx >= FPaths.Count then
    raise EArgumentOutOfRangeException.Create('Index out of range');

  for i := 0 to FShapes.Count - 1 do
  begin
    Shape := TShape(FShapes[i]);
    for j := 0 to Shape.GetPathCount - 1 do
    begin
      PathIdx := Shape.Paths[j];
      if PathIdx = Idx then
{$IFDEF DEBUG}
        raise EInvalidOp.Create('Path is currently in-use by a shape');
{$ELSE}
        raise EInvalidOp.Create('Currently in use');
{$ENDIF}
    end;
  end;
  TPath(FPaths[Idx]).Free;
  FPaths.Delete(Idx);
  for i := 0 to FShapes.Count - 1 do
  begin
    Shape := TShape(FShapes[i]);
    for j := 0 to Shape.GetPathCount - 1 do
    begin
      PathIdx := Shape.Paths[j];
      if PathIdx > Idx then
        Shape.Paths[j] := PathIdx - 1;
    end;
  end;
end;

{ TImage Shapes }

/// <summary>Gets the number of Shapes in this Image.</summary>
/// <returns>Number of Shapes in this Image.</returns>
function TImage.GetShapeCount: Cardinal;
begin
  Result := FShapes.Count;
end;

/// <summary>Gets the Shape at the specified index.</summary>
/// <param name="Idx">Index of the Shape to get.</param>
/// <returns>The Shape at the specified index.</returns>
/// <exception cref="EArgumentOutOfRangeException">Thrown if the provided index is out of range.</exception>
function TImage.GetShape(const Idx: Cardinal): TShape;
begin
  if Idx >= FShapes.Count then
    raise EArgumentOutOfRangeException.Create('Index out of range');

  Result := TShape(FShapes[Idx]);
end;

/// <summary>Replaces the Shape at the specified index.</summary>
/// <param name="Idx">Index of the Shape to replace.</param>
/// <param name="Value">The new Shape.</param>
/// <exception cref="EArgumentOutOfRangeException">Thrown if the provided index is out of range.</exception>
/// <exception cref="ERangeError">Thrown if the Shape contains an invalid Style or Path reference.</exception>
procedure TImage.SetShape(const Idx: Cardinal; const Value: TShape);
begin
  if Idx >= FShapes.Count then
    raise EArgumentOutOfRangeException.Create('Index out of range');

  CheckShape(Value);
  TShape(FShapes[Idx]).Free;
  FShapes[Idx] := Value;
end;

/// <summary>Adds a Shape to this Image.</summary>
/// <param name="Shape">Shape to add.</param>
/// <exception cref="ERangeError">Thrown if the Shape contains an invalid Style or Path reference.</exception>
/// <exception cref="EInvalidOp">Thrown if the maximum number of shapes has been reached.</exception>
procedure TImage.AddShape(Shape: TShape);
begin
  if FShapes.Count >= MaxShapes then
{$IFDEF DEBUG}
    raise EInvalidOp.Create('Maximum number of shapes reached');
{$ELSE}
    raise EInvalidOp.Create('Maximum reached');
{$ENDIF}
  CheckShape(Shape);
  FShapes.Add(Shape);
end;

/// <summary>Removes a Shape from the Image.</summary>
/// <param name="Idx">Index of the Shape to remove.</param>
/// <exception cref="EArgumentOutOfRangeException">Thrown if the provided index is out of range.</exception>
procedure TImage.RemoveShape(const Idx: Cardinal);
begin
  if Idx >= FShapes.Count then
    raise EArgumentOutOfRangeException.Create('Index out of range');

  TShape(FShapes[Idx]).Free;
  FShapes.Delete(Idx);
end;

/// <summary>Checks that all references to Styles and Paths within the Shape are valid for this Image.</summary>
/// <param name="Shape">Shape to check.</param>
/// <exception cref="ERangeError">Thrown if the Shape contains an invalid Style or Path reference.</exception>
procedure TImage.CheckShape(const Shape: TShape);
var
  i: Integer;
  PathIdx: Byte;
begin
  if Shape.Style >= FStyles.Count then
{$IFDEF DEBUG}
    raise ERangeError.Create('Shape contains an invalid style reference');
{$ELSE}
    raise ERangeError.Create('Invalid reference');
{$ENDIF}
  for i := 0 to Shape.GetPathCount - 1 do
  begin
    PathIdx := Shape.Paths[i];
    if PathIdx >= FPaths.Count then
{$IFDEF DEBUG}
      raise ERangeError.Create('Shape contains an invalid path reference');
{$ELSE}
      raise ERangeError.Create('Invalid reference');
{$ENDIF}
  end;
end;

{ TImage Comments }

/// <summary>Gets the author associated with this image.</summary>
/// <returns>The author string.</returns>
/// <exception cref="EAccessViolation">Thrown if the comment type is not TCommentType.Text.</exception>
function TImage.GetAuthor: string;
begin
  case FAuthor.Kind of
    TCommentType.Text:
      Result := FAuthor.Data;
  else
{$IFDEF DEBUG}
    raise EAccessViolation.Create('Invalid comment type for author');
{$ELSE}
    raise EAccessViolation.Create('Invalid type');
{$ENDIF}
  end;
end;

/// <summary>Gets the comment associated with this image.</summary>
/// <returns>The comment string.</returns>
/// <remarks>TODO: Can throw a bunch of exceptions if things go sideways.</remarks>
function TImage.GetComment: string;
begin
  case FComment.Kind of
    TCommentType.Text:
      Result := FComment.Data;
    TCommentType.Path:
    begin
      with TStringList.Create do
      begin
        try
          LoadFromFile(FComment.Data);
          Result := Text;
        finally
          Free;
        end;
      end;
    end;
  else
{$IFDEF DEBUG}
    raise EAccessViolation.Create('Invalid comment type for comment');
{$ELSE}
    raise EAccessViolation.Create('Invalid type');
{$ENDIF}
  end;
end;

/// <summary>Sets the comment associated with this image.</summary>
/// <param name="Value">The comment string to set.</param>
procedure TImage.SetComment(const Value: string);
begin
  FComment.Data := Value;
  FRenderComment := True;
end;

/// <summary>Gets the software associated with this image.</summary>
/// <returns>The software string.</returns>
/// <exception cref="EAccessViolation">Thrown if the comment type is not TCommentType.Text.</exception>
function TImage.GetSoftware: string;
begin
  case FSoftware.Kind of
    TCommentType.Text:
      Result := FSoftware.Data;
  else
{$IFDEF DEBUG}
    raise EAccessViolation.Create('Invalid comment type for software');
{$ELSE}
    raise EAccessViolation.Create('Invalid type');
{$ENDIF}
  end;
end;

end.
