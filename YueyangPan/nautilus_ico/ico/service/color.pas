{*************************************************************}
{                                                             }
{             Haiku Vector Image Format Server                }
{                                                             }
{  Copyright (c) 2025 Alexander Taylor <ajtaylor@fuzyll.com>  }
{                                                             }
{        Licensed under the Apache License, Version 2.0       }
{                                                             }
{*************************************************************}

unit IcoColor;

interface

uses
  SysUtils,
  Classes,
  IcoTransformer;

const
  MaxSteps = 255;
  GradientFlagTransform = 1 shl 1;
  GradientFlagNoAlpha = 1 shl 2;
  GradientFlagGrays = 1 shl 4;

type
  TStyleType = (
    SolidColor = 1,
    Gradient = 2,
    SolidColorNoAlpha = 3,
    SolidGray = 4,
    SolidGrayNoAlpha = 5
  );

  TColor = class
  private
    FRed: Byte;
    FGreen: Byte;
    FBlue: Byte;
    FAlpha: Byte;
  public
    constructor Create; overload;
    constructor Create(Red, Green, Blue, Alpha: Byte); overload;
    class function FromBytes(const Buffer: TBytes; var Idx: Cardinal): TColor;
    function ToBytes: TBytes;
    property Red: Byte read FRed write FRed;
    property Green: Byte read FGreen write FGreen;
    property Blue: Byte read FBlue write FBlue;
    property Alpha: Byte read FAlpha write FAlpha;
  end;

  TGradientType = (
    Linear = 0,
    Circular = 1,
    Diamond = 2,
    Conic = 3,
    Xy = 4,
    SqrtXy = 5
  );

  TGradientStep = record
    Stop: Byte;
    Color: TColor;
  end;

  PGradientStep = ^TGradientStep;

  TGradient = class
  private
    FTransformer: TAffineTransformer;
    FType: TGradientType;
    FSteps: Pointer;
    FStepCount: Integer;
    FAllocatedCount: Integer;

    function GetStep(Idx: Cardinal): TGradientStep;
    procedure SetStep(Idx: Cardinal; const Value: TGradientStep);
    function GetStepPtr(Idx: Integer): PGradientStep; inline;
  public
    constructor Create; overload;
    constructor Create(AType: TGradientType); overload;
    destructor Destroy; override;
    property GradientType: TGradientType read FType write FType;
    property Steps[Idx: Cardinal]: TGradientStep read GetStep write SetStep;
    property Transformer: TAffineTransformer read FTransformer write FTransformer;
    procedure AddStep(Step: TGradientStep); overload;
    procedure AddStep(Step: TGradientStep; Idx: Cardinal); overload;
    procedure RemoveStep(Idx: Cardinal);
    function GetStepCount: Integer;
    procedure EnsureCapacity(MinCount: Integer);
    property StepPtr[Idx: Integer]: PGradientStep read GetStepPtr; default;
    class function FromBytes(const Buffer: TBytes; var Idx: Cardinal): TGradient;
    function ToBytes: TBytes;
  end;

  TStyle = class
  private
    FFlat: Boolean;
    FTransparent: Boolean;
    FColor: TColor;
    FGradient: TGradient;
    procedure UpdateTransparency;
    function GetGradient: TGradient;
    procedure SetGradient(const Value: TGradient);
    function GetColor: TColor;
    procedure SetColor(const Value: TColor);
  public
    constructor Create; overload;
    constructor Create(Color: TColor); overload;
    constructor Create(Gradient: TGradient); overload;
    destructor Destroy; override;
    property Color: TColor read GetColor write SetColor;
    property Gradient: TGradient read GetGradient write SetGradient;
    function GetStep(Idx: Cardinal): TGradientStep;
    procedure SetStep(Idx: Cardinal; const Value: TGradientStep);
    procedure AddStep(Idx: Cardinal; const Value: TGradientStep);
    procedure RemoveStep(Idx: Cardinal);
    function HasGradient: Boolean;
    function HasTransparency: Boolean;
    class function FromBytes(const Buffer: TBytes; var Idx: Cardinal): TStyle;
    function ToBytes: TBytes;
  end;

implementation

{ TColor }

constructor TColor.Create;
begin
  inherited Create;
  FRed := 0;
  FGreen := 0;
  FBlue := 0;
  FAlpha := 0;
end;

constructor TColor.Create(Red, Green, Blue, Alpha: Byte);
begin
  inherited Create;
  FRed := Red;
  FGreen := Green;
  FBlue := Blue;
  FAlpha := Alpha;
end;

/// <summary>Deserializes a Color.</summary>
/// <param name="Buffer">The buffer to deserialize from.</param>
/// <param name="Idx">The index to start deserialization at.</param>
/// <returns>The deserialized Color.</returns>
/// <exception cref="ERangeError">Thrown if the buffer is too small or contains invalid color style type.</exception>
class function TColor.FromBytes(const Buffer: TBytes; var Idx: Cardinal): TColor;
var
  StyleType: TStyleType;
  Gray: Byte;
begin
  Result := TColor.Create;

  // Check buffer bounds for style type
  if Idx >= Length(Buffer) then
{$IFDEF DEBUG}
    raise ERangeError.Create('Buffer too small for color style type');
{$ELSE}
    raise ERangeError.Create('Buffer too small');
{$ENDIF}

  // Validate style type is within valid range before casting
  if (Buffer[Idx] < 1) or (Buffer[Idx] > 5) or (Buffer[Idx] = 2) then
{$IFDEF DEBUG}
    raise ERangeError.Create('Invalid color style type');
{$ELSE}
    raise ERangeError.Create('Invalid type');
{$ENDIF}

  StyleType := TStyleType(Buffer[Idx]);
  Inc(Idx);
  case StyleType of
    TStyleType.SolidGrayNoAlpha:
    begin
      // Check bounds for gray value
      if Idx >= Length(Buffer) then
{$IFDEF DEBUG}
        raise ERangeError.Create('Buffer too small for gray color data');
{$ELSE}
        raise ERangeError.Create('Buffer too small');
{$ENDIF}
      Gray := Buffer[Idx];
      Inc(Idx);
      Result.Red := Gray;
      Result.Green := Gray;
      Result.Blue := Gray;
      Result.Alpha := 255;
    end;
    TStyleType.SolidGray:
    begin
      // Check bounds for gray and alpha values
      if Idx + 1 >= Length(Buffer) then
{$IFDEF DEBUG}
        raise ERangeError.Create('Buffer too small for gray color with alpha data');
{$ELSE}
        raise ERangeError.Create('Buffer too small');
{$ENDIF}
      Gray := Buffer[Idx];
      Inc(Idx);
      Result.Red := Gray;
      Result.Green := Gray;
      Result.Blue := Gray;
      Result.Alpha := Buffer[Idx];
      Inc(Idx);
    end;
    TStyleType.SolidColorNoAlpha:
    begin
      // Check bounds for RGB values
      if Idx + 2 >= Length(Buffer) then
{$IFDEF DEBUG}
        raise ERangeError.Create('Buffer too small for RGB color data');
{$ELSE}
        raise ERangeError.Create('Buffer too small');
{$ENDIF}
      Result.Red := Buffer[Idx];
      Inc(Idx);
      Result.Green := Buffer[Idx];
      Inc(Idx);
      Result.Blue := Buffer[Idx];
      Inc(Idx);
      Result.Alpha := 255;
    end;
    TStyleType.SolidColor:
    begin
      // Check bounds for RGBA values
      if Idx + 3 >= Length(Buffer) then
{$IFDEF DEBUG}
        raise ERangeError.Create('Buffer too small for RGBA color data');
{$ELSE}
        raise ERangeError.Create('Buffer too small');
{$ENDIF}
      Result.Red := Buffer[Idx];
      Inc(Idx);
      Result.Green := Buffer[Idx];
      Inc(Idx);
      Result.Blue := Buffer[Idx];
      Inc(Idx);
      Result.Alpha := Buffer[Idx];
      Inc(Idx);
    end;
  else
{$IFDEF DEBUG}
    raise ERangeError.Create('Not a valid color style');
{$ELSE}
    raise ERangeError.Create('Invalid type');
{$ENDIF}
  end;
end;

/// <summary>Serializes a Color.</summary>
/// <returns>The serialized bytes.</returns>
function TColor.ToBytes: TBytes;
var
  Stream: TMemoryStream;
begin
  Stream := TMemoryStream.Create;
  try
    if (Red = Green) and (Green = Blue) then
    begin
      if Alpha = 255 then
      begin
        Stream.WriteByte(Byte(TStyleType.SolidGrayNoAlpha));
        Stream.WriteByte(Red);
      end
      else
      begin
        Stream.WriteByte(Byte(TStyleType.SolidGray));
        Stream.WriteByte(Red);
        Stream.WriteByte(Alpha);
      end;
    end
    else
    begin
      if Alpha = 255 then
      begin
        Stream.WriteByte(Byte(TStyleType.SolidColorNoAlpha));
        Stream.WriteByte(Red);
        Stream.WriteByte(Green);
        Stream.WriteByte(Blue);
      end
      else
      begin
        Stream.WriteByte(Byte(TStyleType.SolidColor));
        Stream.WriteByte(Red);
        Stream.WriteByte(Green);
        Stream.WriteByte(Blue);
        Stream.WriteByte(Alpha);
      end;
    end;
    SetLength(Result, Stream.Size);
    Stream.Position := 0;
    Stream.ReadBuffer(Result[0], Stream.Size);
  finally
    Stream.Free;
  end;
end;

{ TGradient }

constructor TGradient.Create;
begin
  inherited Create;
  FStepCount := 0;
  FAllocatedCount := 0;
  FSteps := nil;
  FType := TGradientType.Linear;
end;

constructor TGradient.Create(AType: TGradientType);
begin
  inherited Create;
  FStepCount := 0;
  FAllocatedCount := 0;
  FSteps := nil;
  FType := AType;
end;

destructor TGradient.Destroy;
var
  i: Integer;
  StepPtr: PGradientStep;
begin
  for i := 0 to FStepCount - 1 do
  begin
    StepPtr := GetStepPtr(i);
    if StepPtr^.Color <> nil then
      StepPtr^.Color.Free;
  end;
  if FSteps <> nil then
    FreeMem(FSteps);
  inherited Destroy;
end;

/// <summary>Deserializes a Gradient.</summary>
/// <param name="Buffer">The buffer to deserialize from.</param>
/// <param name="Idx">The index to start deserialization at.</param>
/// <returns>The deserialized Gradient.</returns>
/// <exception cref="ERangeError">Thrown if the buffer is too small, contains invalid gradient type, or invalid gradient style.</exception>
class function TGradient.FromBytes(const Buffer: TBytes; var Idx: Cardinal): TGradient;
var
  StyleType: TStyleType;
  Flags, Stops, i: Byte;
  Stop: Byte;
  Gray, Red, Green, Blue, Alpha: Byte;
  GradientStep: TGradientStep;
begin
  // Get the Style type and make sure it's a Gradient
  StyleType := TStyleType(Buffer[Idx]);
  Inc(Idx);
  if StyleType <> TStyleType.Gradient then
{$IFDEF DEBUG}
    raise ERangeError.Create('Not a valid gradient style');
{$ELSE}
    raise ERangeError.Create('Invalid type');
{$ENDIF}

  // Make our Gradient object
  Result := TGradient.Create(TGradientType(Buffer[Idx]));
  Inc(Idx);

  // Read the flags and stop count
  Flags := Buffer[Idx];
  Inc(Idx);
  Stops := Buffer[Idx];
  Inc(Idx);

  // Read the Transform, if we've got one
  if (Flags and GradientFlagTransform) <> 0 then
  begin
    Result.Transformer := TAffineTransformer.FromBytes(Buffer, Idx);
  end;

  // Pull out all the stops
  for i := 0 to Stops - 1 do
  begin

    Stop := Buffer[Idx];
    Inc(Idx);
    GradientStep.Stop := Stop;
    if (Flags and GradientFlagGrays) <> 0 then
    begin
      Gray := Buffer[Idx];
      Inc(Idx);
      if (Flags and GradientFlagNoAlpha) = 0 then
      begin
        Alpha := Buffer[Idx];
        Inc(Idx);
        GradientStep.Color := TColor.Create(Gray, Gray, Gray, Alpha);
        Result.AddStep(GradientStep);
      end
      else
      begin
        GradientStep.Color := TColor.Create(Gray, Gray, Gray, 255);
        Result.AddStep(GradientStep);
      end;
    end
    else
    begin
      Red := Buffer[Idx];
      Inc(Idx);
      Green := Buffer[Idx];
      Inc(Idx);
      Blue := Buffer[Idx];
      Inc(Idx);
      if (Flags and GradientFlagNoAlpha) = 0 then
      begin
        Alpha := Buffer[Idx];
        Inc(Idx);
        GradientStep.Color := TColor.Create(Red, Green, Blue, Alpha);
        Result.AddStep(GradientStep);
      end
      else
      begin
        GradientStep.Color := TColor.Create(Red, Green, Blue, 255);
        Result.AddStep(GradientStep);
      end;
    end;
  end;
end;

/// <summary>Serializes a Gradient.</summary>
/// <returns>The serialized bytes.</returns>
function TGradient.ToBytes: TBytes;
var
  Flags: Byte;
  AllGray, NoAlpha: Boolean;
  i: Integer;
  Step: TGradientStep;
  TransformerBytes: TBytes;
  Stream: TMemoryStream;
begin
  Stream := TMemoryStream.Create;
  try
    // Serialize gradient type
    Stream.WriteByte(Byte(FType));

    // Serialize gradient flags
    Flags := 0;
    AllGray := True;
    NoAlpha := True;
    for i := 0 to FStepCount - 1 do
    begin
      Step := GetStepPtr(i)^;
      if not ((Step.Color.Red = Step.Color.Green) and (Step.Color.Green = Step.Color.Blue)) then
        AllGray := False;
      if Step.Color.Alpha <> 255 then
        NoAlpha := False;
    end;
    if AllGray then
      Flags := Flags or GradientFlagGrays;
    if NoAlpha then
      Flags := Flags or GradientFlagNoAlpha;
    if FTransformer <> nil then
      Flags := Flags or GradientFlagTransform;
    Stream.WriteByte(Flags);

    // Serialize gradient
    Stream.WriteByte(Byte(FStepCount));
    if FTransformer <> nil then
    begin
      TransformerBytes := FTransformer.ToBytes;
      Stream.Write(TransformerBytes[1], Length(TransformerBytes) - 1);
    end;
    for i := 0 to FStepCount - 1 do
    begin
      Step := GetStepPtr(i)^;
      Stream.WriteByte(Step.Stop);
      if AllGray then
      begin
        if NoAlpha then
        begin
          Stream.WriteByte(Step.Color.Red);
        end
        else
        begin
          Stream.WriteByte(Step.Color.Red);
          Stream.WriteByte(Step.Color.Alpha);
        end;
      end
      else
      begin
        if NoAlpha then
        begin
          Stream.WriteByte(Step.Color.Red);
          Stream.WriteByte(Step.Color.Green);
          Stream.WriteByte(Step.Color.Blue);
        end
        else
        begin
          Stream.WriteByte(Step.Color.Red);
          Stream.WriteByte(Step.Color.Green);
          Stream.WriteByte(Step.Color.Blue);
          Stream.WriteByte(Step.Color.Alpha);
        end;
      end;
    end;
    SetLength(Result, Stream.Size);
    Stream.Position := 0;
    Stream.ReadBuffer(Result[0], Stream.Size);
  finally
    Stream.Free;
  end;
end;

procedure TGradient.AddStep(Step: TGradientStep);
begin
  EnsureCapacity(FStepCount + 1);
  GetStepPtr(FStepCount)^ := Step;
  Inc(FStepCount);
end;

procedure TGradient.AddStep(Step: TGradientStep; Idx: Cardinal);
var
  i: Integer;
begin
  if FStepCount >= MaxSteps then
{$IFDEF DEBUG}
    raise EInvalidOp.Create('Maximum number of gradient steps reached');
{$ELSE}
    raise EInvalidOp.Create('Maximum reached');
{$ENDIF}
  EnsureCapacity(FStepCount + 1);
  // Shift elements to the right to make room for insertion
  for i := FStepCount - 1 downto Integer(Idx) do
    GetStepPtr(i + 1)^ := GetStepPtr(i)^;
  GetStepPtr(Idx)^ := Step;
  Inc(FStepCount);
end;

function TGradient.GetStep(Idx: Cardinal): TGradientStep;
begin
  Result := GetStepPtr(Idx)^;
end;

procedure TGradient.SetStep(Idx: Cardinal; const Value: TGradientStep);
var
  StepPtr: PGradientStep;
begin
  StepPtr := GetStepPtr(Idx);
  // Free the old color before replacing
  if StepPtr^.Color <> nil then
    StepPtr^.Color.Free;
  StepPtr^ := Value;
end;

procedure TGradient.RemoveStep(Idx: Cardinal);
var
  i: Integer;
  StepPtr: PGradientStep;
begin
  // Free the color being removed
  StepPtr := GetStepPtr(Idx);
  if StepPtr^.Color <> nil then
    StepPtr^.Color.Free;

  // Shift elements left to fill the gap
  for i := Integer(Idx) to FStepCount - 2 do
    GetStepPtr(i)^ := GetStepPtr(i + 1)^;
  Dec(FStepCount);
end;

function TGradient.GetStepCount: Integer;
begin
  Result := FStepCount;
end;

/// <summary>Gets direct pointer to gradient step for ultra-fast access.</summary>
/// <param name="Idx">Index of the step.</param>
/// <returns>Direct pointer to the gradient step - no bounds checking.</returns>
function TGradient.GetStepPtr(Idx: Integer): PGradientStep;
begin
  Result := PGradientStep(PtrUInt(FSteps) + PtrUInt(Idx * SizeOf(TGradientStep)));
end;

/// <summary>Ensures the memory block can hold at least MinCount steps.</summary>
/// <param name="MinCount">Minimum number of steps to allocate space for.</param>
procedure TGradient.EnsureCapacity(MinCount: Integer);
begin
  if MinCount > FAllocatedCount then
  begin
    FAllocatedCount := MinCount * 2; // Double allocation for efficiency
    if FAllocatedCount < 4 then
      FAllocatedCount := 4; // Minimum allocation
    ReallocMem(FSteps, FAllocatedCount * SizeOf(TGradientStep));
  end;
end;

{ TStyle }

constructor TStyle.Create;
begin
  inherited Create;
  FFlat := True;
  FTransparent := False;
end;

constructor TStyle.Create(Color: TColor);
begin
  inherited Create;
  FFlat := True;
  FColor := Color;
  if Color.Alpha <> 255 then
    FTransparent := True
  else
    FTransparent := False;
end;

constructor TStyle.Create(Gradient: TGradient);
var
  i: Integer;
  Step: TGradientStep;
begin
  inherited Create;
  FFlat := False;
  FGradient := Gradient;
  FTransparent := False;
  for i := 0 to Gradient.GetStepCount - 1 do
  begin
    Step := Gradient.Steps[i];
    if Step.Color.Alpha <> 255 then
    begin
      FTransparent := True;
      Break;
    end;
  end;
end;

destructor TStyle.Destroy;
begin
  if not FFlat then
  begin
    if FGradient <> nil then
      FGradient.Free;
  end
  else
  begin
    if FColor <> nil then
      FColor.Free;
  end;
  inherited Destroy;
end;

/// <summary>Deserializes a Style.</summary>
/// <param name="Buffer">The buffer to deserialize from.</param>
/// <param name="Idx">The index to start deserialization at.</param>
/// <returns>The deserialized Style.</returns>
/// <exception cref="ERangeError">Thrown if the buffer is too small or contains invalid style type.</exception>
class function TStyle.FromBytes(const Buffer: TBytes; var Idx: Cardinal): TStyle;
var
  StyleType: TStyleType;
  Color: TColor;
  Gradient: TGradient;
begin
  // Check buffer bounds for style type
  if Idx >= Length(Buffer) then
{$IFDEF DEBUG}
    raise ERangeError.Create('Buffer too small for style type');
{$ELSE}
    raise ERangeError.Create('Buffer too small');
{$ENDIF}

  StyleType := TStyleType(Buffer[Idx]);
  case StyleType of
    TStyleType.SolidGrayNoAlpha,
    TStyleType.SolidGray,
    TStyleType.SolidColorNoAlpha,
    TStyleType.SolidColor:
    begin
      Color := TColor.FromBytes(Buffer, Idx);
      Result := TStyle.Create(Color);
    end;
    TStyleType.Gradient:
    begin
      Gradient := TGradient.FromBytes(Buffer, Idx);
      Result := TStyle.Create(Gradient);
    end;
  else
{$IFDEF DEBUG}
    raise ERangeError.Create('Not a valid style type');
{$ELSE}
    raise ERangeError.Create('Invalid type');
{$ENDIF}
  end;
end;

/// <summary>Serializes a Style.</summary>
/// <returns>The serialized bytes.</returns>
function TStyle.ToBytes: TBytes;
var
  ColorBytes, GradientBytes: TBytes;
  Stream: TMemoryStream;
begin
  Stream := TMemoryStream.Create;
  try
    if FFlat then
    begin
      ColorBytes := FColor.ToBytes;
      Stream.Write(ColorBytes[0], Length(ColorBytes));
    end
    else
    begin
      Stream.WriteByte(Byte(TStyleType.Gradient));
      GradientBytes := FGradient.ToBytes;
      Stream.Write(GradientBytes[0], Length(GradientBytes));
    end;
    SetLength(Result, Stream.Size);
    Stream.Position := 0;
    Stream.ReadBuffer(Result[0], Stream.Size);
  finally
    Stream.Free;
  end;
end;

function TStyle.GetColor: TColor;
begin
  Result := FColor;
end;

procedure TStyle.SetColor(const Value: TColor);
begin
  if not FFlat and (FGradient <> nil) then
  begin
    FGradient.Free;
    FGradient := nil;
  end;
  FColor := Value;
  FFlat := True;
  UpdateTransparency;
end;

function TStyle.GetGradient: TGradient;
begin
  Result := FGradient;
end;

procedure TStyle.SetGradient(const Value: TGradient);
begin
  if FFlat and (FColor <> nil) then
  begin
    FColor.Free;
    FColor := nil;
  end;
  FGradient := Value;
  FFlat := False;
  UpdateTransparency;
end;

function TStyle.GetStep(Idx: Cardinal): TGradientStep;
begin
  if not FFlat then
    Result := FGradient.Steps[Idx]
  else
{$IFDEF DEBUG}
    raise EAccessViolation.Create('Style does not contain gradient');
{$ELSE}
    raise EAccessViolation.Create('Invalid operation');
{$ENDIF}
end;

procedure TStyle.SetStep(Idx: Cardinal; const Value: TGradientStep);
begin
  if not FFlat then
  begin
    FGradient.Steps[Idx] := Value;
    UpdateTransparency;
  end
  else
{$IFDEF DEBUG}
    raise EAccessViolation.Create('Style does not contain gradient');
{$ELSE}
    raise EAccessViolation.Create('Invalid operation');
{$ENDIF}
end;

procedure TStyle.AddStep(Idx: Cardinal; const Value: TGradientStep);
begin
  if not FFlat then
  begin
    FGradient.AddStep(Value, Idx);
    UpdateTransparency;
  end
  else
{$IFDEF DEBUG}
    raise EAccessViolation.Create('Style does not contain gradient');
{$ELSE}
    raise EAccessViolation.Create('Invalid operation');
{$ENDIF}
end;

procedure TStyle.RemoveStep(Idx: Cardinal);
begin
  if not FFlat then
  begin
    FGradient.RemoveStep(Idx);
    UpdateTransparency;
  end
  else
{$IFDEF DEBUG}
    raise EAccessViolation.Create('Style does not contain gradient');
{$ELSE}
    raise EAccessViolation.Create('Invalid operation');
{$ENDIF}
end;

function TStyle.HasGradient: Boolean;
begin
  Result := not FFlat;
end;

function TStyle.HasTransparency: Boolean;
begin
  Result := FTransparent;
end;

procedure TStyle.UpdateTransparency;
var
  i: Integer;
  Step: TGradientStep;
begin
  if FFlat then
  begin
    if FColor.Alpha <> 255 then
      FTransparent := True
    else
      FTransparent := False;
  end
  else
  begin
    FTransparent := False;
    for i := 0 to FGradient.GetStepCount - 1 do
    begin
      Step := FGradient.Steps[i];
      if Step.Color.Alpha <> 255 then
      begin
        FTransparent := True;
        Exit;
      end;
    end;
  end;
end;

end.
