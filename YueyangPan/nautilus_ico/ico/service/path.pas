{*************************************************************}
{                                                             }
{             Haiku Vector Image Format Server                }
{                                                             }
{  Copyright (c) 2025 Alexander Taylor <ajtaylor@fuzyll.com>  }
{                                                             }
{        Licensed under the Apache License, Version 2.0       }
{                                                             }
{*************************************************************}

unit IcoPath;

interface

uses
  SysUtils,
  Classes,
  IcoPoint;

const
  MaxPoints = 255;
  PathIsClosed = 1 shl 1;
  PathHasCommands = 1 shl 2;
  PathHasNoCurves = 1 shl 3;

type
  TPathCommand = (
    HorizontalLine = 0,
    VerticalLine = 1,
    Line = 2,
    Curve = 3
  );

  TPath = class
  private
    FClosed: Boolean;
    FCurved: Boolean;
    FPoints: TList;
    function GetPoint(const Idx: Cardinal): TPoint;
    procedure SetPoint(const Idx: Cardinal; const Value: TPoint);
  public
    constructor Create;
    destructor Destroy; override;
    class function FromBytes(const Buffer: TBytes; var Idx: Cardinal): TPath;
    function ToBytes: TBytes;
    function GetPoints: TList;
    procedure AddPoint(Point: TPoint); overload;
    procedure AddPoint(Point: TPoint; const Idx: Cardinal); overload;
    procedure RemovePoint(const Idx: Cardinal);
    property Points[Idx: Cardinal]: TPoint read GetPoint write SetPoint; default;
    property IsClosed: Boolean read FClosed write FClosed;
    property IsCurved: Boolean read FCurved write FCurved;
  end;

implementation

{ TPath }

constructor TPath.Create;
begin
  inherited Create;
  FPoints := TList.Create;
  FClosed := False;
  FCurved := False;
end;

destructor TPath.Destroy;
var
  i: Integer;
begin
  for i := 0 to FPoints.Count - 1 do
    TPoint(FPoints[i]).Free;
  FPoints.Free;
  inherited Destroy;
end;

{ TPath Deserialize }

/// <summary>Deserializes a Path.</summary>
/// <param name="Buffer">The buffer to deserialize from.</param>
/// <param name="Idx">The index to start deserialization at.</param>
/// <returns>The deserialized Path.</returns>
/// <exception cref="ERangeError">Thrown if the buffer is too small, contains invalid path command values, or insufficient coordinate data.</exception>
class function TPath.FromBytes(const Buffer: TBytes; var Idx: Cardinal): TPath;
var
  Flags, NPoints, i, j, NCmdBytes, CmdByte: Byte;
  Cmds: array of TPathCommand;
  Last: TPoint;
  X, Y, XIn, YIn, XOut, YOut: Single;
begin
  // Create Path object
  Result := TPath.Create;

  // Check buffer bounds for flags and point count
  if Idx + 1 >= Length(Buffer) then
{$IFDEF DEBUG}
    raise ERangeError.Create('Buffer too small for path flags and point count');
{$ELSE}
    raise ERangeError.Create('Buffer too small');
{$ENDIF}

  // Read flags
  Flags := Buffer[Idx];
  Inc(Idx);

  // Read number of points
  NPoints := Buffer[Idx];
  Inc(Idx);

  // Set closed state
  if (Flags and PathIsClosed) <> 0 then
    Result.IsClosed := True;

  // Read points
  if (Flags and PathHasCommands) <> 0 then
  begin
    // There are path commands, we need to read them first
    NCmdBytes := (NPoints + 3) div 4;
    SetLength(Cmds, NPoints + 3);

    // Check buffer bounds for command bytes
    if Idx + NCmdBytes - 1 >= Length(Buffer) then
{$IFDEF DEBUG}
      raise ERangeError.Create('Buffer too small for path command data');
{$ELSE}
      raise ERangeError.Create('Buffer too small');
{$ENDIF}

    for j := 0 to NCmdBytes - 1 do
    begin
      CmdByte := Buffer[Idx];
      Inc(Idx);

      // Validate path commands are within valid range (0-3)
      if ((CmdByte and 3) > 3) or (((CmdByte shr 2) and 3) > 3) or
         (((CmdByte shr 4) and 3) > 3) or ((CmdByte shr 6) > 3) then
{$IFDEF DEBUG}
        raise ERangeError.Create('Invalid path command value');
{$ELSE}
        raise ERangeError.Create('Invalid value');
{$ENDIF}

      Cmds[j * 4] := TPathCommand(CmdByte and 3);
      Cmds[(j * 4) + 1] := TPathCommand((CmdByte shr 2) and 3);
      Cmds[(j * 4) + 2] := TPathCommand((CmdByte shr 4) and 3);
      Cmds[(j * 4) + 3] := TPathCommand(CmdByte shr 6);
    end;

    // Use each path command to identify its corresponding point
    Last := TPoint.Create;
    for j := 0 to NPoints - 1 do
    begin
      case Cmds[j] of
        TPathCommand.HorizontalLine:
        begin
          // Read in a horizontal line
          X := TPoint.ReadCoordinate(Buffer, Idx);
          Result.AddPoint(TPoint.Create(X, Last.Y));
          Last.X := X;
        end;
        TPathCommand.VerticalLine:
        begin
          // Read in a vertical line
          Y := TPoint.ReadCoordinate(Buffer, Idx);
          Result.AddPoint(TPoint.Create(Last.X, Y));
          Last.Y := Y;
        end;
        TPathCommand.Line:
        begin
          // Read in a line
          X := TPoint.ReadCoordinate(Buffer, Idx);
          Y := TPoint.ReadCoordinate(Buffer, Idx);
          Result.AddPoint(TPoint.Create(X, Y));
          Last.X := X;
          Last.Y := Y;
        end;
        TPathCommand.Curve:
        begin
          // Read in a curve
          Result.IsCurved := True;
          X := TPoint.ReadCoordinate(Buffer, Idx);
          Y := TPoint.ReadCoordinate(Buffer, Idx);
          XIn := TPoint.ReadCoordinate(Buffer, Idx);
          YIn := TPoint.ReadCoordinate(Buffer, Idx);
          XOut := TPoint.ReadCoordinate(Buffer, Idx);
          YOut := TPoint.ReadCoordinate(Buffer, Idx);
          Result.AddPoint(TPoint.Create(X, Y, XIn, YIn, XOut, YOut));
          Last.X := X;
          Last.Y := Y;
        end;
      end;
    end;
    Last.Free;
  end
  else
  begin
    // No path commands here, just some points
    for i := 0 to NPoints - 1 do
    begin
      if (Flags and PathHasNoCurves) = 0 then
      begin
        // Read in a curve
        Result.IsCurved := True;
        X := TPoint.ReadCoordinate(Buffer, Idx);
        Y := TPoint.ReadCoordinate(Buffer, Idx);
        XIn := TPoint.ReadCoordinate(Buffer, Idx);
        YIn := TPoint.ReadCoordinate(Buffer, Idx);
        XOut := TPoint.ReadCoordinate(Buffer, Idx);
        YOut := TPoint.ReadCoordinate(Buffer, Idx);
        Result.AddPoint(TPoint.Create(X, Y, XIn, YIn, XOut, YOut));
      end
      else
      begin
        // Read in a line
        X := TPoint.ReadCoordinate(Buffer, Idx);
        Y := TPoint.ReadCoordinate(Buffer, Idx);
        Result.AddPoint(TPoint.Create(X, Y));
      end;
    end;
  end;
end;

{ TPath Serialize }

/// <summary>Serializes a Path.</summary>
/// <returns>The serialized bytes.</returns>
function TPath.ToBytes: TBytes;
var
  Flag: Byte;
  Straight, Line, Curve, i, CommandLen, PlainLen, CmdIdx, CmdLoc: Integer;
  CurPoint: TPoint;
  PrevPoint: TPoint;
  Command: TPathCommand;
  Stream: TMemoryStream;
  TempCmdByte: Byte;
begin
  Stream := TMemoryStream.Create;

  try
    // Set closed state
    Flag := 0;
    if FClosed then
      Flag := Flag or PathIsClosed;

    // Count how many points of each type we have in this Path
    Straight := 0;
    Line := 0;
    Curve := 0;
    PrevPoint := TPoint.Create;
    for i := 0 to FPoints.Count - 1 do
    begin
      CurPoint := Self.Points[i];
      if (CurPoint.X = CurPoint.XIn) and (CurPoint.XIn = CurPoint.XOut) and
         (CurPoint.Y = CurPoint.YIn) and (CurPoint.YIn = CurPoint.YOut) then
      begin
        if (CurPoint.X = PrevPoint.X) or (CurPoint.Y = PrevPoint.Y) then
          Inc(Straight)
        else
          Inc(Line);
      end
      else
        Inc(Curve);
      if i = 0 then
        PrevPoint.Free;
      PrevPoint := CurPoint;
    end;

    // Determine whether we'll be more efficient as a plain or complex Path
    CommandLen := FPoints.Count + (Straight * 2) + (Line * 4) + (Curve * 12);
    PlainLen := (Straight * 4) + (Line * 4) + (Curve * 12);
    if Curve = 0 then
      Flag := Flag or PathHasNoCurves;
    if CommandLen < PlainLen then
      Flag := Flag or PathHasCommands;

    // Write flags and number of points
    Stream.WriteByte(Flag);
    Stream.WriteByte(FPoints.Count);

    // Make space for the commands, if we are a complex Path
    if CommandLen < PlainLen then
    begin
      CmdIdx := Stream.Position;
      for i := 0 to (FPoints.Count + 3) div 4 - 1 do
        Stream.WriteByte(0);
    end;

    // Write points
    if CommandLen < PlainLen then
    begin
      // Write them out as a complex Path
      CmdLoc := 0;
      PrevPoint := TPoint.Create;
      for i := 0 to FPoints.Count - 1 do
      begin
        CurPoint := Self.Points[i];

        // Figure out how we should write this point
        if (CurPoint.X = CurPoint.XIn) and (CurPoint.XIn = CurPoint.XOut) and
            (CurPoint.Y = CurPoint.YIn) and (CurPoint.YIn = CurPoint.YOut) then
        begin
          if (CurPoint.X = PrevPoint.X) or (CurPoint.Y = PrevPoint.Y) then
          begin
            if CurPoint.X = PrevPoint.X then
            begin
              // Write out as a vertical line
              Command := TPathCommand.VerticalLine;
              TPoint.WriteCoordinate(Stream, CurPoint.Y);
            end
            else
            begin
              // Write out as a horizontal line
              Command := TPathCommand.HorizontalLine;
              TPoint.WriteCoordinate(Stream, CurPoint.X);
            end;
          end
          else
          begin
            // Write out as a line
            Command := TPathCommand.Line;
            TPoint.WriteCoordinate(Stream, CurPoint.X);
            TPoint.WriteCoordinate(Stream, CurPoint.Y);
          end;
        end
        else
        begin
          // Write out as a curve
          Command := TPathCommand.Curve;
          TPoint.WriteCoordinate(Stream, CurPoint.X);
          TPoint.WriteCoordinate(Stream, CurPoint.Y);
          TPoint.WriteCoordinate(Stream, CurPoint.XIn);
          TPoint.WriteCoordinate(Stream, CurPoint.YIn);
          TPoint.WriteCoordinate(Stream, CurPoint.XOut);
          TPoint.WriteCoordinate(Stream, CurPoint.YOut);
        end;

        // Move to the next point
        if i = 0 then
          PrevPoint.Free;
        PrevPoint := CurPoint;

        // Update the commands
        Stream.Position := CmdIdx;
        Stream.Read(TempCmdByte, 1);
        TempCmdByte := TempCmdByte or (Byte(Command) shl (2 * CmdLoc));
        Stream.Position := CmdIdx;
        Stream.Write(TempCmdByte, 1);
        Stream.Position := Stream.Size;

        // Advance location within the command section
        Inc(CmdLoc);
        if CmdLoc > 3 then
        begin
          CmdLoc := 0;
          Inc(CmdIdx);
        end;
      end;
    end
    else
    begin
      // Write them out as a plain Path
      for i := 0 to FPoints.Count - 1 do
      begin
        CurPoint := Self.Points[i];
        if Curve = 0 then
        begin
          TPoint.WriteCoordinate(Stream, CurPoint.X);
          TPoint.WriteCoordinate(Stream, CurPoint.Y);
        end
        else
        begin
          TPoint.WriteCoordinate(Stream, CurPoint.X);
          TPoint.WriteCoordinate(Stream, CurPoint.Y);
          TPoint.WriteCoordinate(Stream, CurPoint.XIn);
          TPoint.WriteCoordinate(Stream, CurPoint.YIn);
          TPoint.WriteCoordinate(Stream, CurPoint.XOut);
          TPoint.WriteCoordinate(Stream, CurPoint.YOut);
        end;
      end;
    end;

    // Return our serialized Path
    SetLength(Result, Stream.Size);
    Stream.Position := 0;
    Stream.ReadBuffer(Result[0], Stream.Size);
  finally
    Stream.Free;
  end;
end;

{ TPath Points }

/// <summary>Gets the full list of Points in this Path.</summary>
/// <returns>List of all Points in this Path.</returns>
function TPath.GetPoints: TList;
begin
  Result := FPoints;
end;

/// <summary>Gets the Point at the specified index.</summary>
/// <param name="Idx">Index of the Point to get.</param>
/// <returns>The Point at the specified index.</returns>
/// <exception cref="EArgumentOutOfRangeException">Thrown if the provided index is out of range.</exception>
function TPath.GetPoint(const Idx: Cardinal): TPoint;
begin
  if Idx >= FPoints.Count then
    raise EArgumentOutOfRangeException.Create('Index out of range');

  Result := TPoint(FPoints[Idx]);
end;

/// <summary>Replaces the Point at the specified index.</summary>
/// <param name="Idx">Index of the Point to replace.</param>
/// <param name="Value">The new Point value.</param>
/// <exception cref="EArgumentOutOfRangeException">Thrown if the provided index is out of range.</exception>
procedure TPath.SetPoint(const Idx: Cardinal; const Value: TPoint);
begin
  if Idx >= FPoints.Count then
    raise EArgumentOutOfRangeException.Create('Index out of range');

  TPoint(FPoints[Idx]).Free;
  FPoints[Idx] := Value;
end;

/// <summary>Adds a new Point to this Path.</summary>
/// <param name="Point">The Point to add.</param>
/// <exception cref="EInvalidOp">Thrown if the maximum number of points has been reached.</exception>
procedure TPath.AddPoint(Point: TPoint);
begin
  if FPoints.Count >= MaxPoints then
{$IFDEF DEBUG}
    raise EInvalidOp.Create('Maximum number of points reached');
{$ELSE}
    raise EInvalidOp.Create('Maximum reached');
{$ENDIF}
  FPoints.Add(Point);
end;

/// <summary>Inserts a new Point to this Path at a specific index.</summary>
/// <param name="Point">The Point to add.</param>
/// <param name="Idx">Index at which to insert the Point.</param>
/// <exception cref="EArgumentOutOfRangeException">Thrown if the provided index is out of range.</exception>
procedure TPath.AddPoint(Point: TPoint; const Idx: Cardinal);
begin
  if Idx > FPoints.Count then
    raise EArgumentOutOfRangeException.Create('Index out of range');

  FPoints.Insert(Idx, Point);
end;

/// <summary>Removes a Point from this Path.</summary>
/// <param name="Idx">Index of the Point to remove.</param>
/// <exception cref="EArgumentOutOfRangeException">Thrown if the provided index is out of range.</exception>
procedure TPath.RemovePoint(const Idx: Cardinal);
begin
  if Idx >= FPoints.Count then
    raise EArgumentOutOfRangeException.Create('Index out of range');

  TPoint(FPoints[Idx]).Free;
  FPoints.Delete(Idx);
end;

end.
