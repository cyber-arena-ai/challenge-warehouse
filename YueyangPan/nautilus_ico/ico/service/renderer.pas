{*************************************************************}
{                                                             }
{             Haiku Vector Image Format Server                }
{                                                             }
{  Copyright (c) 2025 Alexander Taylor <ajtaylor@fuzyll.com>  }
{                                                             }
{        Licensed under the Apache License, Version 2.0       }
{                                                             }
{*************************************************************}

unit IcoRenderer;

interface

uses
  SysUtils,
  Classes,
  Math,
  FPImage,
  FPCanvas,
  FPImgCanv,
  FPWritePNG,
  IcoColor,
  IcoPath,
  IcoShape,
  IcoPoint,
  IcoTransformer,
  IcoImage;

type
  TTransformMatrix = record
    M11, M12, M13: Single; // [sx  shx tx]  Row 1: scale-x, shear-x, translate-x
    M21, M22, M23: Single; // [shy sy  ty]  Row 2: shear-y, scale-y, translate-y
    M31, M32, M33: Single; // [0   0   1 ]  Row 3: homogeneous coordinates
  end;

  TTransformStack = class
  private
    FStack: array of TTransformMatrix;
    FStackDepth: Integer;
    FCurrent: TTransformMatrix;
  public
    constructor Create;
    procedure Push;
    procedure Pop;
    procedure TransformPoint(var X, Y: Single);
    procedure LoadIdentity;
    procedure LoadWorldTransform(CanvasWidth, CanvasHeight: Integer);
    procedure MultiplyBy(const AT: TAffineTransformer);
    function GetCurrentMatrix: TTransformMatrix;
    function GetInverse: TTransformMatrix;
  end;

  TRenderer = class
  private
    FBitmap: TFPMemoryImage;
    FCanvas: TFPImageCanvas;
    FTransforms: TTransformStack;
    FWidth, FHeight: Integer;
    procedure InitializeBitmap(Width, Height: Integer);
    procedure RenderShape(Shape: TShape; Image: TObject);
    procedure RenderPath(Path: TPath; Style: TStyle);
    procedure FillPath(Path: TPath; Style: TStyle);
    procedure StrokePath(Path: TPath; Style: TStyle; Width: Single; LineJoin: TLineJoin; LineCap: TLineCap; MiterLimit: Byte);
    procedure ContourPath(Path: TPath; Style: TStyle; Width: Single; LineJoin: Byte; MiterLimit: Byte);
    procedure RenderContourStroke(const Points: array of Classes.TPoint; Count: Integer; StrokeWidth: Integer; LineJoin: Byte; MiterLimit: Byte; IsClosed: Boolean);
    procedure GenerateStrokeOutline(const Points: array of Classes.TPoint; Count: Integer; HalfWidth: Single; LineJoin: Byte; MiterLimit: Byte; IsClosed: Boolean; var LeftOutline: array of Classes.TPoint; var LeftCount: Integer; var RightOutline: array of Classes.TPoint; var RightCount: Integer);
    procedure RenderStrokePolygon(const LeftOutline: array of Classes.TPoint; LeftCount: Integer; const RightOutline: array of Classes.TPoint; RightCount: Integer);
    function CalculateLineIntersection(x1, y1, x2, y2, x3, y3, x4, y4: Single; var ix, iy: Single): Boolean;
    procedure FillSolidPolygon(const Points: array of Classes.TPoint; Count: Integer; Color: TFPColor);
    procedure RenderStroke(const Points: array of Classes.TPoint; Count: Integer; StrokeWidth: Integer; LineJoin: Byte; MiterLimit: Byte; LineCap: TLineCap; IsClosed: Boolean);
    procedure GenerateStrokeOutlineWithCaps(const Points: array of Classes.TPoint; Count: Integer; HalfWidth: Single; LineJoin: Byte; MiterLimit: Byte; LineCap: TLineCap; IsClosed: Boolean; var LeftOutline: array of Classes.TPoint; var LeftCount: Integer; var RightOutline: array of Classes.TPoint; var RightCount: Integer);
    procedure GenerateLineCap(X, Y, DX, DY: Single; HalfWidth: Single; LineCap: TLineCap; var CapPoints: array of Classes.TPoint; var CapCount: Integer);
    procedure RenderLineCap(X, Y: Integer; DX, DY: Single; Width: Integer; LineCap: TLineCap; Color: TFPColor);
    function IsPointACurve(const Point: IcoPoint.TPoint): Boolean;
    procedure FlattenCurvesToPoints(Path: TPath; var Points: array of Classes.TPoint; var Count: Integer);
    function TransformPath(Path: TPath): TPath;
    function StyleToFPColor(Style: TStyle): TFPColor;
    function GetRenderScale: Single;
    function ShouldRenderShape(Shape: TShape): Boolean;
    procedure FillPathWithGradient(Path: TPath; Style: TStyle);
    function CalculateGradientColor(const Gradient: TGradient; X, Y: Single): TFPColor;
    function InterpolateColor(const Color1, Color2: TColor; t: Single): TColor;
    function IsPointInPolygon(X, Y: Integer; const Points: array of Classes.TPoint; Count: Integer): Boolean;
    procedure FillPolygonScanline(const Points: array of Classes.TPoint; Count: Integer; Style: TStyle);
    function CalculatePixelCoverage(X, Y: Integer; const Points: array of Classes.TPoint; Count: Integer): Single;
    procedure ApplyAntiAliasing(const Points: array of Classes.TPoint; Count: Integer; Style: TStyle);
  public
    constructor Create(Width, Height: Integer);
    destructor Destroy; override;
    procedure RenderImage(Image: TObject);
    procedure ExportToPNG(var Buffer: TBytes); overload;
    procedure ExportToPNG(var Buffer: TBytes; const Text: TStringList); overload;
    property Canvas: TFPImageCanvas read FCanvas;
    property Bitmap: TFPMemoryImage read FBitmap;
  end;

  TCustomPNGWriter = class
  private
    FBaseWriter: TFPWriterPNG;
    procedure WriteUInt32BE(Stream: TStream; Value: Cardinal);
    function CalculateCRC32(const Data: TBytes): Cardinal;
    procedure AddTextChunk(var PNGData: TBytes; const Text: TStringList);
    function FindIENDChunk(const PNGData: TBytes): Integer;
  public
    constructor Create;
    destructor Destroy; override;
    procedure WriteToBuffer(Bitmap: TFPMemoryImage; var Buffer: TBytes; const Text: TStringList); overload;
    property BaseWriter: TFPWriterPNG read FBaseWriter;
  end;

  // Matrix helper functions
  function CreateIdentityMatrix: TTransformMatrix;
  function MultiplyMatrix(const A, B: TTransformMatrix): TTransformMatrix;
  function InvertMatrix(const M: TTransformMatrix): TTransformMatrix;
  function CreateWorldMatrix(CanvasWidth, CanvasHeight: Integer): TTransformMatrix;
  function AffineToMatrix(const AT: TAffineTransformer): TTransformMatrix;

implementation

{ Matrix Helper Functions }

/// <summary>Creates a 3x3 identity transformation matrix.</summary>
/// <returns>An identity matrix with 1.0 on the diagonal and 0.0 elsewhere.</returns>
function CreateIdentityMatrix: TTransformMatrix;
begin
  Result.M11 := 1.0; Result.M12 := 0.0; Result.M13 := 0.0;
  Result.M21 := 0.0; Result.M22 := 1.0; Result.M23 := 0.0;
  Result.M31 := 0.0; Result.M32 := 0.0; Result.M33 := 1.0;
end;

/// <summary>Multiplies two 3x3 transformation matrices using A * B order.</summary>
/// <param name="A">The first matrix.</param>
/// <param name="B">The second matrix.</param>
/// <returns>The result of A * B matrix multiplication.</returns>
/// <remarks> When used with row vectors, this applies transformation B first, then A.
function MultiplyMatrix(const A, B: TTransformMatrix): TTransformMatrix;
begin
  Result.M11 := A.M11 * B.M11 + A.M12 * B.M21;
  Result.M12 := A.M11 * B.M12 + A.M12 * B.M22;
  Result.M13 := A.M11 * B.M13 + A.M12 * B.M23 + A.M13;

  Result.M21 := A.M21 * B.M11 + A.M22 * B.M21;
  Result.M22 := A.M21 * B.M12 + A.M22 * B.M22;
  Result.M23 := A.M21 * B.M13 + A.M22 * B.M23 + A.M23;

  Result.M31 := 0.0;
  Result.M32 := 0.0;
  Result.M33 := 1.0;
end;

/// <summary>Inverts a 3x3 transformation matrix.</summary>
/// <param name="M">The matrix to invert.</param>
/// <returns>The inverted matrix. If the matrix is singular, returns an identity matrix.</returns>
function InvertMatrix(const M: TTransformMatrix): TTransformMatrix;
var
  Det: Single;
begin
  Det := M.M11 * M.M22 - M.M12 * M.M21;
  if Abs(Det) < 1e-9 then // Check for singularity
  begin
    Result := CreateIdentityMatrix;
    Exit;
  end;

  Result.M11 := M.M22 / Det;
  Result.M12 := -M.M12 / Det;
  Result.M13 := (M.M12 * M.M23 - M.M13 * M.M22) / Det;

  Result.M21 := -M.M21 / Det;
  Result.M22 := M.M11 / Det;
  Result.M23 := (M.M13 * M.M21 - M.M11 * M.M23) / Det;

  Result.M31 := 0.0;
  Result.M32 := 0.0;
  Result.M33 := 1.0;
end;

/// <summary>Creates a world transformation matrix to map HVIF coordinates to canvas pixels.</summary>
/// <param name="CanvasWidth">The width of the output canvas in pixels.</param>
/// <param name="CanvasHeight">The height of the output canvas in pixels.</param>
/// <returns>A transformation matrix that scales and centers HVIF coordinates for the canvas.</returns>
/// <remarks>This matrix is applied last in the transformation chain.</remarks>
function CreateWorldMatrix(CanvasWidth, CanvasHeight: Integer): TTransformMatrix;
var
  Scale: Single;
begin
  // Most HVIF icons use coordinates in roughly 0-64 range
  // This is the practical coordinate space, not the theoretical -128 to +192
  // Scale based on typical icon coordinate usage for proper sizing
  // Use 65.0 instead of 64.0 to ensure coordinates like 63.x stay within canvas bounds
  Scale := Min(CanvasWidth, CanvasHeight) / 65.0;

  Result := CreateIdentityMatrix;
  Result.M11 := Scale;                              // Scale X
  Result.M22 := Scale;                              // Scale Y
  Result.M13 := CanvasWidth / 2.0 - 32.0 * Scale;   // Translate X to center
  Result.M23 := CanvasHeight / 2.0 - 32.0 * Scale;  // Translate Y to center
end;

/// <summary>Converts an affine transformer to a 3x3 transformation matrix.</summary>
/// <param name="AT">The affine transformer to convert.</param>
/// <returns>A 3x3 matrix representing the same transformation.</returns>
function AffineToMatrix(const AT: TAffineTransformer): TTransformMatrix;
begin
  Result.M11 := AT.SX;  Result.M12 := AT.SHX; Result.M13 := AT.TX;
  Result.M21 := AT.SHY; Result.M22 := AT.SY;  Result.M23 := AT.TY;
  Result.M31 := 0.0;    Result.M32 := 0.0;   Result.M33 := 1.0;
end;

{ TTransformStack }

constructor TTransformStack.Create;
begin
  inherited Create;
  SetLength(FStack, 16); // Initial stack size
  FStackDepth := 0;
  LoadIdentity;
end;

/// <summary>Loads the identity matrix as the current transformation.</summary>
procedure TTransformStack.LoadIdentity;
begin
  FCurrent := CreateIdentityMatrix;
end;

/// <summary>Loads a world transformation matrix for the given canvas dimensions.</summary>
/// <param name="CanvasWidth">The width of the canvas in pixels.</param>
/// <param name="CanvasHeight">The height of the canvas in pixels.</param>
procedure TTransformStack.LoadWorldTransform(CanvasWidth, CanvasHeight: Integer);
begin
  FCurrent := CreateWorldMatrix(CanvasWidth, CanvasHeight);
end;

/// <summary>Multiplies the current transformation with an affine transformer.</summary>
/// <param name="AT">The affine transformer to apply.</param>
/// <remarks>This applies the transformation AT first, then the current transformation,
/// maintaining proper order for shape-local to world coordinate conversion.</remarks>
procedure TTransformStack.MultiplyBy(const AT: TAffineTransformer);
begin
  FCurrent := MultiplyMatrix(FCurrent, AffineToMatrix(AT));
end;

/// <summary>Pushes the current transformation onto the stack.</summary>
procedure TTransformStack.Push;
begin
  if FStackDepth >= Length(FStack) then
    SetLength(FStack, Length(FStack) * 2);

  FStack[FStackDepth] := FCurrent;
  Inc(FStackDepth);
end;

/// <summary>Pops the previous transformation from the stack, restoring the previous state.</summary>
/// <remarks>Does nothing if the stack is empty.</remarks>
procedure TTransformStack.Pop;
begin
  if FStackDepth > 0 then
  begin
    Dec(FStackDepth);
    FCurrent := FStack[FStackDepth];
  end;
end;

/// <summary>Transforms a point using the current transformation matrix.</summary>
/// <param name="X">The X coordinate to transform (modified in place).</param>
/// <param name="Y">The Y coordinate to transform (modified in place).</param>
/// <remarks>Uses row vector convention: [X Y 1] * Matrix = [NewX NewY 1].</remarks>
procedure TTransformStack.TransformPoint(var X, Y: Single);
var
  NewX, NewY: Single;
begin
  NewX := X * FCurrent.M11 + Y * FCurrent.M12 + FCurrent.M13;
  NewY := X * FCurrent.M21 + Y * FCurrent.M22 + FCurrent.M23;
  X := NewX;
  Y := NewY;
end;

/// <summary>Gets the current transformation matrix.</summary>
/// <returns>The current transformation matrix.</returns>
function TTransformStack.GetCurrentMatrix: TTransformMatrix;
begin
  Result := FCurrent;
end;

/// <summary>Gets the inverse of the current transformation matrix.</summary>
/// <returns>The inverted current transformation matrix.</returns>
function TTransformStack.GetInverse: TTransformMatrix;
begin
  Result := InvertMatrix(FCurrent);
end;

{ TRenderer }

constructor TRenderer.Create(Width, Height: Integer);
begin
  inherited Create;
  FWidth := Width;
  FHeight := Height;
  FTransforms := TTransformStack.Create;
  InitializeBitmap(Width, Height);
end;

destructor TRenderer.Destroy;
begin
  FTransforms.Free;
  FCanvas.Free;
  FBitmap.Free;
  inherited Destroy;
end;

/// <summary>Initializes the internal bitmap and canvas for rendering.</summary>
/// <param name="Width">The width of the bitmap in pixels.</param>
/// <param name="Height">The height of the bitmap in pixels.</param>
procedure TRenderer.InitializeBitmap(Width, Height: Integer);
begin
  FBitmap := TFPMemoryImage.Create(Width, Height);
  FCanvas := TFPImageCanvas.Create(FBitmap);

  // Clear to transparent white
  FBitmap.UsePalette := False;
  FCanvas.Brush.Style := bsSolid;
  FCanvas.Brush.FPColor := colTransparent;
  FCanvas.Rectangle(0, 0, Width, Height);
end;

/// <summary>Renders a complete HVIF image to the internal bitmap.</summary>
/// <param name="Image">The TImage object to render.</param>
/// <remarks>Sets up world transformation and renders all shapes in the image.</remarks>
procedure TRenderer.RenderImage(Image: TObject);
var
  IcoImage: TObject;
  i: Integer;
begin
  IcoImage := Image;

  // Set up world transform
  FTransforms.LoadWorldTransform(FWidth, FHeight);

  // Render each shape
  for i := 0 to (IcoImage as TImage).GetShapeCount - 1 do
  begin
    try
      RenderShape((IcoImage as TImage).Shapes[i], IcoImage);
    except
      on E: Exception do
        // Skip shapes that fail to render
        Continue;
    end;
  end;
end;

/// <summary>Renders a single shape from an image.</summary>
/// <param name="Shape">The shape to render.</param>
/// <param name="Image">The parent image containing styles and paths.</param>
/// <remarks>Handles level-of-detail visibility and applies shape transformers.</remarks>
procedure TRenderer.RenderShape(Shape: TShape; Image: TObject);
var
  IcoImage: TObject;
  Style: TStyle;
  i, j: Integer;
  Path: TPath;
  Transformer: TTransformer;
  HasContour: Boolean;
  ContourWidth: Single;
  ContourLineJoin: Byte;
  ContourMiterLimit: Byte;
  HasStroke: Boolean;
  StrokeWidth: Single;
  StrokeLineJoin: TLineJoin;
  StrokeLineCap: TLineCap;
  StrokeMiterLimit: Byte;
begin
  IcoImage := Image;

  // Check if this shape should be rendered at the current scale
  if not ShouldRenderShape(Shape) then
  begin
{$IFDEF DEBUG}
    WriteLn('Shape with style ', Shape.Style, ' filtered out by visibility (', Shape.MinVisibility:0:2, '-', Shape.MaxVisibility:0:2, '), scale=', GetRenderScale:0:2);
{$ENDIF}
    Exit;
  end;

  try
    // Get the style for this shape
    Style := (IcoImage as TImage).Styles[Shape.Style];
{$IFDEF DEBUG}
    WriteLn('Rendering shape with style ', Shape.Style, ' (paths: ', Shape.GetPathCount, ', transformers: ', Shape.GetTransformerCount, ')');
{$ENDIF}

    // Push current transform state before applying shape transforms
    FTransforms.Push;
    try
      // Analyze transformers to determine rendering approach
      HasContour := False;
      ContourWidth := 1.0;
      ContourLineJoin := 0; // Miter join
      ContourMiterLimit := 4;
      HasStroke := False;
      StrokeWidth := 1.0;
      StrokeLineJoin := TLineJoin.ljMiter;
      StrokeLineCap := TLineCap.lcButt;
      StrokeMiterLimit := 4;

      // Apply shape transformers
      for i := 0 to Shape.GetTransformerCount - 1 do
      begin
        Transformer := Shape.Transformers[i];
        if Transformer is TAffineTransformer then
          FTransforms.MultiplyBy(TAffineTransformer(Transformer))
        else if Transformer is TContourTransformer then
        begin
          HasContour := True;
          ContourWidth := (Transformer as TContourTransformer).Width;
          ContourLineJoin := (Transformer as TContourTransformer).LineJoin;
          ContourMiterLimit := (Transformer as TContourTransformer).MiterLimit;
        end
        else if Transformer is TStrokeTransformer then
        begin
          HasStroke := True;
          StrokeWidth := (Transformer as TStrokeTransformer).Width;
          StrokeLineJoin := (Transformer as TStrokeTransformer).LineJoin;
          StrokeLineCap := (Transformer as TStrokeTransformer).LineCap;
          StrokeMiterLimit := (Transformer as TStrokeTransformer).MiterLimit;
        end;
      end;

      // Render each path in this shape
      for j := 0 to Shape.GetPathCount - 1 do
      begin
        try
          Path := (IcoImage as TImage).Paths[Shape.Paths[j]];
          if HasContour then
            ContourPath(Path, Style, ContourWidth, ContourLineJoin, ContourMiterLimit)
          else if HasStroke then
            StrokePath(Path, Style, StrokeWidth, StrokeLineJoin, StrokeLineCap, StrokeMiterLimit)
          else
            RenderPath(Path, Style);
        except
          on E: Exception do
            // Skip paths that fail to render
            Continue;
        end;
      end;

    finally
      // Pop transform state to restore previous state
      FTransforms.Pop;
    end;

  except
    on E: Exception do
      // Skip this entire shape if style lookup fails
      Exit;
  end;
end;

/// <summary>Renders a path with the specified style.</summary>
/// <param name="Path">The path to render.</param>
/// <param name="Style">The style to apply (color or gradient).</param>
procedure TRenderer.RenderPath(Path: TPath; Style: TStyle);
begin
  // Render the path based on its properties
  // For shapes with paths, we typically want to fill them
  FillPath(Path, Style);
end;

/// <summary>Fills a path with solid color or gradient.</summary>
/// <param name="Path">The path to fill.</param>
/// <param name="Style">The style containing color or gradient information.</param>
/// <remarks>Handles both curved and straight paths with anti-aliasing.</remarks>
procedure TRenderer.FillPath(Path: TPath; Style: TStyle);
var
  TransformedPath: TPath;
  TransformedPoints: array[0..1023] of Classes.TPoint;
  Count: Integer;
  i: Integer;
  X, Y: Single;
  Color: TFPColor;
  Point: IcoPoint.TPoint;
begin
  if Path.GetPoints.Count = 0 then Exit;

  {$IFDEF DEBUG}
  WriteLn('FillPath: Rendering path with ', Path.GetPoints.Count, ' points, style has gradient: ', Style.HasGradient);
  {$ENDIF}

  // Use gradient fill if the style has a gradient
  if Style.HasGradient then
  begin
    FillPathWithGradient(Path, Style);
    Exit;
  end;

  // Transform the path for solid color fills
  TransformedPath := TransformPath(Path);
  try
    Count := 0;

    // Handle curved vs non-curved paths differently
    if TransformedPath.IsCurved then
    begin
      // For curved paths, flatten Bézier curves to line segments
      FlattenCurvesToPoints(TransformedPath, TransformedPoints, Count);
    end
    else
    begin
      // For non-curved paths, convert points directly to canvas coordinates
      for i := 0 to TransformedPath.GetPoints.Count - 1 do
      begin
        if Count >= High(TransformedPoints) then Break;

        Point := TransformedPath.Points[i];
        X := Point.X;
        Y := Point.Y;

        // Apply transform stack to convert from HVIF space to pixel coordinates
        FTransforms.TransformPoint(X, Y);

        {$IFDEF DEBUG}
        WriteLn('Point ', i, ': (', Point.X:0:2, ',', Point.Y:0:2, ') -> (', X:0:2, ',', Y:0:2, ') -> pixel (', Round(X), ',', Round(Y), ')');
        {$ENDIF}

        // Store transformed point
        TransformedPoints[Count].X := Round(X);
        TransformedPoints[Count].Y := Round(Y);
        Inc(Count);
      end;
    end;

    if Count >= 3 then
    begin
      {$IFDEF DEBUG}
      WriteLn('FillPath: Got ', Count, ' transformed points, filling polygon');
      {$ENDIF}

      // Use proper scanline polygon filling
      if TransformedPath.IsClosed then
      begin
        FillPolygonScanline(TransformedPoints, Count, Style);
        // Apply anti-aliasing for smoother edges
        ApplyAntiAliasing(TransformedPoints, Count, Style);
      end
      else
      begin
        // For open paths, draw as lines
        Color := StyleToFPColor(Style);
        FCanvas.Pen.Style := psSolid;
        FCanvas.Pen.FPColor := Color;
        FCanvas.Pen.Width := 1;
        FCanvas.MoveTo(TransformedPoints[0].X, TransformedPoints[0].Y);
        for i := 1 to Count - 1 do
          FCanvas.LineTo(TransformedPoints[i].X, TransformedPoints[i].Y);
      end;
    end
    else if Count = 1 then
    begin
      // Single point - draw a small dot
      Color := StyleToFPColor(Style);
      FCanvas.Brush.FPColor := Color;
      FCanvas.Pen.FPColor := Color;
      FCanvas.Ellipse(TransformedPoints[0].X - 1, TransformedPoints[0].Y - 1,
                      TransformedPoints[0].X + 1, TransformedPoints[0].Y + 1);
    end;

  finally
    TransformedPath.Free;
  end;
end;

/// <summary>Renders a path with TStrokeTransformer using proper line joins and line caps.</summary>
/// <param name="Path">The path to stroke.</param>
/// <param name="Style">The style for the stroke color.</param>
/// <param name="Width">The stroke width in HVIF units.</param>
/// <param name="LineJoin">Line join style (ljMiter, ljRound, ljBevel).</param>
/// <param name="LineCap">Line cap style (lcButt, lcRound, lcSquare).</param>
/// <param name="MiterLimit">Miter limit for miter joins.</param>
procedure TRenderer.StrokePath(Path: TPath; Style: TStyle; Width: Single; LineJoin: TLineJoin; LineCap: TLineCap; MiterLimit: Byte);
var
  TransformedPath: TPath;
  TransformedPoints: array[0..1023] of Classes.TPoint;
  Count: Integer;
  i: Integer;
  X, Y: Single;
  Color: TFPColor;
  Point: IcoPoint.TPoint;
  StrokeWidth: Integer;
  LineJoinByte: Byte;
begin
  if Path.GetPoints.Count = 0 then Exit;

  // Transform the path to screen coordinates
  TransformedPath := TransformPath(Path);
  try
    // Convert path points to canvas coordinates
    Count := 0;
    for i := 0 to TransformedPath.GetPoints.Count - 1 do
    begin
      if Count >= High(TransformedPoints) then Break;

      Point := TransformedPath.Points[i];
      X := Point.X;
      Y := Point.Y;

      // Apply transform stack to convert from HVIF space to pixel coordinates
      FTransforms.TransformPoint(X, Y);

      // Store transformed point
      TransformedPoints[Count].X := Round(X);
      TransformedPoints[Count].Y := Round(Y);
      Inc(Count);
    end;

    if Count >= 2 then
    begin
      // Calculate stroke width in pixels
      StrokeWidth := Round(Abs(Width) * Min(FWidth, FHeight) / 64.0);
      if StrokeWidth < 1 then StrokeWidth := 1;

      // Set up stroke style
      Color := StyleToFPColor(Style);
      FCanvas.Pen.Style := psSolid;
      FCanvas.Pen.FPColor := Color;
      FCanvas.Brush.Style := bsClear;

      // Convert TLineJoin enum to byte for reusing existing geometry code
      case LineJoin of
        TLineJoin.ljMiter: LineJoinByte := 0;
        TLineJoin.ljRound: LineJoinByte := 1;
        TLineJoin.ljBevel: LineJoinByte := 2;
      else
        LineJoinByte := 0; // Default to miter
      end;

      // Render the stroke with proper line joins and caps
      RenderStroke(TransformedPoints, Count, StrokeWidth, LineJoinByte, MiterLimit, LineCap, TransformedPath.IsClosed);
    end
    else if Count = 1 then
    begin
      // Single point - draw a dot with line cap style
      Color := StyleToFPColor(Style);
      StrokeWidth := Round(Abs(Width) * Min(FWidth, FHeight) / 64.0);
      if StrokeWidth < 1 then StrokeWidth := 1;

      RenderLineCap(TransformedPoints[0].X, TransformedPoints[0].Y, 0, 1, StrokeWidth, LineCap, Color);
    end;

  finally
    TransformedPath.Free;
  end;
end;

/// <summary>Renders a path with contour stroke using specified width and line join style.</summary>
/// <param name="Path">The path to render with contour stroke.</param>
/// <param name="Style">The style for the stroke color.</param>
/// <param name="Width">The stroke width in HVIF units.</param>
/// <param name="LineJoin">Line join style (0=miter, 1=round, 2=bevel).</param>
/// <param name="MiterLimit">Miter limit for miter joins.</param>
procedure TRenderer.ContourPath(Path: TPath; Style: TStyle; Width: Single; LineJoin: Byte; MiterLimit: Byte);
var
  TransformedPath: TPath;
  TransformedPoints: array[0..1023] of Classes.TPoint;
  Count: Integer;
  i: Integer;
  X, Y: Single;
  Color: TFPColor;
  Point: IcoPoint.TPoint;
  StrokeWidth: Integer;
begin
  if Path.GetPoints.Count = 0 then Exit;

  // Transform the path to screen coordinates
  TransformedPath := TransformPath(Path);
  try
    // Convert path points to canvas coordinates
    Count := 0;
    for i := 0 to TransformedPath.GetPoints.Count - 1 do
    begin
      if Count >= High(TransformedPoints) then Break;

      Point := TransformedPath.Points[i];
      X := Point.X;
      Y := Point.Y;

      // Apply transform stack to convert from HVIF space to pixel coordinates
      FTransforms.TransformPoint(X, Y);

      // Store transformed point
      TransformedPoints[Count].X := Round(X);
      TransformedPoints[Count].Y := Round(Y);
      Inc(Count);
    end;

    if Count >= 2 then
    begin
      // Calculate stroke width in pixels
      StrokeWidth := Round(Abs(Width) * Min(FWidth, FHeight) / 64.0);
      if StrokeWidth < 1 then StrokeWidth := 1;

      // Set up stroke style
      Color := StyleToFPColor(Style);
      FCanvas.Pen.Style := psSolid;
      FCanvas.Pen.FPColor := Color;
      FCanvas.Brush.Style := bsClear;

      // Render the contour stroke with line joins
      RenderContourStroke(TransformedPoints, Count, StrokeWidth, LineJoin, MiterLimit, TransformedPath.IsClosed);
    end
    else if Count = 1 then
    begin
      // Single point - draw a dot
      Color := StyleToFPColor(Style);
      StrokeWidth := Round(Abs(Width) * Min(FWidth, FHeight) / 64.0);
      if StrokeWidth < 1 then StrokeWidth := 1;

      FCanvas.Brush.FPColor := Color;
      FCanvas.Pen.FPColor := Color;
      FCanvas.Ellipse(TransformedPoints[0].X - StrokeWidth, TransformedPoints[0].Y - StrokeWidth,
                      TransformedPoints[0].X + StrokeWidth, TransformedPoints[0].Y + StrokeWidth);
    end;

  finally
    TransformedPath.Free;
  end;
end;

/// <summary>Renders a contour stroke with proper line joins.</summary>
/// <param name="Points">Array of points defining the path.</param>
/// <param name="Count">Number of points in the path.</param>
/// <param name="StrokeWidth">Width of the stroke in pixels.</param>
/// <param name="LineJoin">Line join style (0=miter, 1=round, 2=bevel).</param>
/// <param name="MiterLimit">Miter limit for miter joins.</param>
/// <param name="IsClosed">Whether the path should be closed.</param>
procedure TRenderer.RenderContourStroke(const Points: array of Classes.TPoint; Count: Integer; StrokeWidth: Integer; LineJoin: Byte; MiterLimit: Byte; IsClosed: Boolean);
var
  i: Integer;
  HalfWidth: Single;
  LeftOutline, RightOutline: array[0..1023] of Classes.TPoint;
  LeftCount, RightCount: Integer;
begin
  if Count < 2 then Exit;

  HalfWidth := StrokeWidth / 2.0;

  if StrokeWidth <= 1 then
  begin
    // For very thin strokes, use simple line drawing
    FCanvas.Pen.Width := 1;
    FCanvas.MoveTo(Points[0].X, Points[0].Y);
    for i := 1 to Count - 1 do
      FCanvas.LineTo(Points[i].X, Points[i].Y);
    if IsClosed and (Count >= 3) then
      FCanvas.LineTo(Points[0].X, Points[0].Y);
  end
  else
  begin
    // Generate stroke outline with proper line joins
    GenerateStrokeOutline(Points, Count, HalfWidth, LineJoin, MiterLimit, IsClosed, LeftOutline, LeftCount, RightOutline, RightCount);

    // Render the stroke as a filled polygon
    RenderStrokePolygon(LeftOutline, LeftCount, RightOutline, RightCount);
  end;
end;

/// <summary>Generates the left and right outline points for a stroke with proper line joins.</summary>
/// <param name="Points">Array of points defining the path centerline.</param>
/// <param name="Count">Number of points in the path.</param>
/// <param name="HalfWidth">Half the stroke width.</param>
/// <param name="LineJoin">Line join style (0=miter, 1=round, 2=bevel).</param>
/// <param name="MiterLimit">Miter limit for miter joins.</param>
/// <param name="IsClosed">Whether the path should be closed.</param>
/// <param name="LeftOutline">Output array for left outline points.</param>
/// <param name="LeftCount">Number of points in left outline.</param>
/// <param name="RightOutline">Output array for right outline points.</param>
/// <param name="RightCount">Number of points in right outline.</param>
procedure TRenderer.GenerateStrokeOutline(const Points: array of Classes.TPoint; Count: Integer; HalfWidth: Single; LineJoin: Byte; MiterLimit: Byte; IsClosed: Boolean; var LeftOutline: array of Classes.TPoint; var LeftCount: Integer; var RightOutline: array of Classes.TPoint; var RightCount: Integer);
var
  i: Integer;
  x1, y1, x2, y2, x0, y0: Single;
  dx1, dy1, dx2, dy2: Single;
  len1, len2: Single;
  nx1, ny1, nx2, ny2: Single; // Normalized direction vectors
  px1, py1, px2, py2: Single; // Perpendicular vectors (outward normals)
  leftX1, leftY1, rightX1, rightY1: Single;
  leftX2, leftY2, rightX2, rightY2: Single;
  jx, jy: Single; // Join intersection point
  MiterLength: Single;
  angle, stepAngle: Single;
  steps, step: Integer;
begin
  LeftCount := 0;
  RightCount := 0;

  if Count < 2 then Exit;

  // Generate outline for each line segment with proper joins
  for i := 0 to Count - 1 do
  begin
    if (LeftCount >= High(LeftOutline) - 10) or (RightCount >= High(RightOutline) - 10) then
      Break;

    // Get current point
    x1 := Points[i].X;
    y1 := Points[i].Y;

    // Get next point (with wrapping for closed paths)
    if i < Count - 1 then
    begin
      x2 := Points[i + 1].X;
      y2 := Points[i + 1].Y;
    end
    else if IsClosed then
    begin
      x2 := Points[0].X;
      y2 := Points[0].Y;
    end
    else
    begin
      // End of open path - add end cap points
      if i > 0 then
      begin
        // Previous point for end cap calculation
        x0 := Points[i - 1].X;
        y0 := Points[i - 1].Y;
        dx1 := x1 - x0;
        dy1 := y1 - y0;
        len1 := Sqrt(dx1 * dx1 + dy1 * dy1);
        if len1 > 0.001 then
        begin
          nx1 := dx1 / len1;
          ny1 := dy1 / len1;
          px1 := -ny1 * HalfWidth;
          py1 := nx1 * HalfWidth;

          // Add end cap points
          LeftOutline[LeftCount].X := Round(x1 + px1);
          LeftOutline[LeftCount].Y := Round(y1 + py1);
          Inc(LeftCount);
          RightOutline[RightCount].X := Round(x1 - px1);
          RightOutline[RightCount].Y := Round(y1 - py1);
          Inc(RightCount);
        end;
      end;
      Break;
    end;

    // Calculate direction vector and perpendicular for current segment
    dx1 := x2 - x1;
    dy1 := y2 - y1;
    len1 := Sqrt(dx1 * dx1 + dy1 * dy1);

    if len1 < 0.001 then Continue; // Skip degenerate segments

    // Normalize direction and calculate perpendicular
    nx1 := dx1 / len1;
    ny1 := dy1 / len1;
    px1 := -ny1 * HalfWidth; // Left perpendicular
    py1 := nx1 * HalfWidth;

    // Calculate outline points for this segment
    leftX1 := x1 + px1;
    leftY1 := y1 + py1;
    rightX1 := x1 - px1;
    rightY1 := y1 - py1;
    leftX2 := x2 + px1;
    leftY2 := y2 + py1;
    rightX2 := x2 - px1;
    rightY2 := y2 - py1;

    if i = 0 then
    begin
      // First segment - add start points
      LeftOutline[LeftCount].X := Round(leftX1);
      LeftOutline[LeftCount].Y := Round(leftY1);
      Inc(LeftCount);
      RightOutline[RightCount].X := Round(rightX1);
      RightOutline[RightCount].Y := Round(rightY1);
      Inc(RightCount);
    end
    else
    begin
      // Join with previous segment
      // Get previous segment direction
      x0 := Points[i - 1].X;
      y0 := Points[i - 1].Y;
      dx2 := x1 - x0;
      dy2 := y1 - y0;
      len2 := Sqrt(dx2 * dx2 + dy2 * dy2);

      if len2 > 0.001 then
      begin
        nx2 := dx2 / len2;
        ny2 := dy2 / len2;
        px2 := -ny2 * HalfWidth;
        py2 := nx2 * HalfWidth;

        // Calculate line join based on join type
        case LineJoin of
          0: // Miter join
          begin
            // Calculate miter intersection
            if CalculateLineIntersection(x0 + px2, y0 + py2, x1 + px2, y1 + py2,
                                       x1 + px1, y1 + py1, x2 + px1, y2 + py1, jx, jy) then
            begin
              MiterLength := Sqrt((jx - x1) * (jx - x1) + (jy - y1) * (jy - y1));
              if (MiterLimit = 0) or (MiterLength <= HalfWidth * MiterLimit) then
              begin
                // Use miter point
                LeftOutline[LeftCount].X := Round(jx);
                LeftOutline[LeftCount].Y := Round(jy);
                Inc(LeftCount);
              end
              else
              begin
                // Miter limit exceeded - fall back to bevel
                LeftOutline[LeftCount].X := Round(x1 + px2);
                LeftOutline[LeftCount].Y := Round(y1 + py2);
                Inc(LeftCount);
                LeftOutline[LeftCount].X := Round(leftX1);
                LeftOutline[LeftCount].Y := Round(leftY1);
                Inc(LeftCount);
              end;
            end
            else
            begin
              // Lines are parallel - use simple connection
              LeftOutline[LeftCount].X := Round(leftX1);
              LeftOutline[LeftCount].Y := Round(leftY1);
              Inc(LeftCount);
            end;

            // Right side miter
            if CalculateLineIntersection(x0 - px2, y0 - py2, x1 - px2, y1 - py2,
                                       x1 - px1, y1 - py1, x2 - px1, y2 - py1, jx, jy) then
            begin
              MiterLength := Sqrt((jx - x1) * (jx - x1) + (jy - y1) * (jy - y1));
              if (MiterLimit = 0) or (MiterLength <= HalfWidth * MiterLimit) then
              begin
                RightOutline[RightCount].X := Round(jx);
                RightOutline[RightCount].Y := Round(jy);
                Inc(RightCount);
              end
              else
              begin
                RightOutline[RightCount].X := Round(x1 - px2);
                RightOutline[RightCount].Y := Round(y1 - py2);
                Inc(RightCount);
                RightOutline[RightCount].X := Round(rightX1);
                RightOutline[RightCount].Y := Round(rightY1);
                Inc(RightCount);
              end;
            end
            else
            begin
              RightOutline[RightCount].X := Round(rightX1);
              RightOutline[RightCount].Y := Round(rightY1);
              Inc(RightCount);
            end;
          end;

          1: // Round join
          begin
            // Calculate angle between segments
            angle := ArcTan2(ny1, nx1) - ArcTan2(ny2, nx2);
            while angle < -Pi do angle := angle + 2 * Pi;
            while angle > Pi do angle := angle - 2 * Pi;

            steps := Round(Abs(angle) * HalfWidth / 2) + 2;
            if steps > 16 then steps := 16; // Limit arc detail

            stepAngle := angle / steps;

            // Generate arc points for round join
            for step := 0 to steps do
            begin
              if (LeftCount >= High(LeftOutline)) or (RightCount >= High(RightOutline)) then Break;

              angle := ArcTan2(ny2, nx2) + step * stepAngle;
              LeftOutline[LeftCount].X := Round(x1 - Sin(angle) * HalfWidth);
              LeftOutline[LeftCount].Y := Round(y1 + Cos(angle) * HalfWidth);
              Inc(LeftCount);
              RightOutline[RightCount].X := Round(x1 + Sin(angle) * HalfWidth);
              RightOutline[RightCount].Y := Round(y1 - Cos(angle) * HalfWidth);
              Inc(RightCount);
            end;
          end;

          2: // Bevel join
          begin
            // Simple bevel - just connect the endpoints
            LeftOutline[LeftCount].X := Round(x1 + px2);
            LeftOutline[LeftCount].Y := Round(y1 + py2);
            Inc(LeftCount);
            LeftOutline[LeftCount].X := Round(leftX1);
            LeftOutline[LeftCount].Y := Round(leftY1);
            Inc(LeftCount);

            RightOutline[RightCount].X := Round(x1 - px2);
            RightOutline[RightCount].Y := Round(y1 - py2);
            Inc(RightCount);
            RightOutline[RightCount].X := Round(rightX1);
            RightOutline[RightCount].Y := Round(rightY1);
            Inc(RightCount);
          end;
        end;
      end
      else
      begin
        // Degenerate previous segment
        LeftOutline[LeftCount].X := Round(leftX1);
        LeftOutline[LeftCount].Y := Round(leftY1);
        Inc(LeftCount);
        RightOutline[RightCount].X := Round(rightX1);
        RightOutline[RightCount].Y := Round(rightY1);
        Inc(RightCount);
      end;
    end;

    // Add end point of current segment
    if (i = Count - 1) and not IsClosed then
    begin
      LeftOutline[LeftCount].X := Round(leftX2);
      LeftOutline[LeftCount].Y := Round(leftY2);
      Inc(LeftCount);
      RightOutline[RightCount].X := Round(rightX2);
      RightOutline[RightCount].Y := Round(rightY2);
      Inc(RightCount);
    end;
  end;
end;

/// <summary>Calculates the intersection point of two lines.</summary>
/// <param name="x1, y1, x2, y2">First line endpoints.</param>
/// <param name="x3, y3, x4, y4">Second line endpoints.</param>
/// <param name="ix, iy">Intersection point (output).</param>
/// <returns>True if lines intersect, False if parallel.</returns>
function TRenderer.CalculateLineIntersection(x1, y1, x2, y2, x3, y3, x4, y4: Single; var ix, iy: Single): Boolean;
var
  denom, ua: Single;
begin
  Result := False;
  denom := (y4 - y3) * (x2 - x1) - (x4 - x3) * (y2 - y1);

  if Abs(denom) < 0.0001 then Exit; // Lines are parallel

  ua := ((x4 - x3) * (y1 - y3) - (y4 - y3) * (x1 - x3)) / denom;

  ix := x1 + ua * (x2 - x1);
  iy := y1 + ua * (y2 - y1);
  Result := True;
end;

/// <summary>Renders a stroke as a filled polygon using left and right outlines.</summary>
/// <param name="LeftOutline">Left outline points.</param>
/// <param name="LeftCount">Number of left outline points.</param>
/// <param name="RightOutline">Right outline points.</param>
/// <param name="RightCount">Number of right outline points.</param>
procedure TRenderer.RenderStrokePolygon(const LeftOutline: array of Classes.TPoint; LeftCount: Integer; const RightOutline: array of Classes.TPoint; RightCount: Integer);
var
  AllPoints: array[0..2047] of Classes.TPoint;
  TotalCount, i: Integer;
begin
  if (LeftCount < 2) or (RightCount < 2) then Exit;

  TotalCount := 0;

  // Add left outline points
  for i := 0 to LeftCount - 1 do
  begin
    if TotalCount >= High(AllPoints) then Break;
    AllPoints[TotalCount] := LeftOutline[i];
    Inc(TotalCount);
  end;

  // Add right outline points in reverse order
  for i := RightCount - 1 downto 0 do
  begin
    if TotalCount >= High(AllPoints) then Break;
    AllPoints[TotalCount] := RightOutline[i];
    Inc(TotalCount);
  end;

  // Fill the stroke polygon using direct pixel rendering
  if TotalCount >= 6 then
  begin
    FCanvas.Brush.Style := bsSolid;
    FCanvas.Brush.FPColor := FCanvas.Pen.FPColor;

    // Use direct polygon filling approach for solid color strokes
    FillSolidPolygon(AllPoints, TotalCount, FCanvas.Pen.FPColor);
  end;
end;

/// <summary>Fills a polygon with a solid color using scanline algorithm.</summary>
/// <param name="Points">Array of polygon vertices.</param>
/// <param name="Count">Number of vertices in the polygon.</param>
/// <param name="Color">Solid color to fill with.</param>
procedure TRenderer.FillSolidPolygon(const Points: array of Classes.TPoint; Count: Integer; Color: TFPColor);
var
  MinY, MaxY, Y, X: Integer;
  i, j: Integer;
  Intersections: array[0..1023] of Integer;
  IntersectionCount: Integer;
  x1, y1, x2, y2: Integer;
begin
  if Count < 3 then Exit;

  // Find Y bounds
  MinY := Points[0].Y;
  MaxY := Points[0].Y;
  for i := 1 to Count - 1 do
  begin
    if Points[i].Y < MinY then MinY := Points[i].Y;
    if Points[i].Y > MaxY then MaxY := Points[i].Y;
  end;

  // Clamp to canvas bounds
  if MinY < 0 then MinY := 0;
  if MaxY >= FHeight then MaxY := FHeight - 1;

  // For each scanline
  for Y := MinY to MaxY do
  begin
    // Find intersections with polygon edges
    IntersectionCount := 0;
    j := Count - 1;

    for i := 0 to Count - 1 do
    begin
      x1 := Points[j].X;
      y1 := Points[j].Y;
      x2 := Points[i].X;
      y2 := Points[i].Y;

      // Check if scanline intersects this edge
      if ((y1 > Y) <> (y2 > Y)) then
      begin
        // Calculate intersection X coordinate
        X := Round(x1 + (Y - y1) * (x2 - x1) / (y2 - y1));

        // Store intersection if within canvas bounds
        if (X >= 0) and (X < FWidth) and (IntersectionCount < High(Intersections)) then
        begin
          Intersections[IntersectionCount] := X;
          Inc(IntersectionCount);
        end;
      end;

      j := i;
    end;

    // Sort intersections
    if IntersectionCount > 1 then
    begin
      // Simple bubble sort for intersections
      for i := 0 to IntersectionCount - 2 do
        for j := i + 1 to IntersectionCount - 1 do
          if Intersections[i] > Intersections[j] then
          begin
            X := Intersections[i];
            Intersections[i] := Intersections[j];
            Intersections[j] := X;
          end;

      // Fill between pairs of intersections
      i := 0;
      while i < IntersectionCount - 1 do
      begin
        for X := Intersections[i] to Intersections[i + 1] - 1 do
        begin
          if (X >= 0) and (X < FWidth) then
            FBitmap.Colors[X, Y] := Color;
        end;
        Inc(i, 2); // Move to next pair
      end;
    end;
  end;
end;

/// <summary>Renders a stroke with proper line joins and line caps.</summary>
/// <param name="Points">Array of points defining the path centerline.</param>
/// <param name="Count">Number of points in the path.</param>
/// <param name="StrokeWidth">Width of the stroke in pixels.</param>
/// <param name="LineJoin">Line join style (0=miter, 1=round, 2=bevel).</param>
/// <param name="MiterLimit">Miter limit for miter joins.</param>
/// <param name="LineCap">Line cap style for path endpoints.</param>
/// <param name="IsClosed">Whether the path should be closed.</param>
procedure TRenderer.RenderStroke(const Points: array of Classes.TPoint; Count: Integer; StrokeWidth: Integer; LineJoin: Byte; MiterLimit: Byte; LineCap: TLineCap; IsClosed: Boolean);
var
  i: Integer;
  HalfWidth: Single;
  LeftOutline, RightOutline: array[0..1023] of Classes.TPoint;
  LeftCount, RightCount: Integer;
begin
  if Count < 2 then Exit;

  HalfWidth := StrokeWidth / 2.0;

  if StrokeWidth <= 1 then
  begin
    // For very thin strokes, use simple line drawing
    FCanvas.Pen.Width := 1;
    FCanvas.MoveTo(Points[0].X, Points[0].Y);
    for i := 1 to Count - 1 do
      FCanvas.LineTo(Points[i].X, Points[i].Y);
    if IsClosed and (Count >= 3) then
      FCanvas.LineTo(Points[0].X, Points[0].Y);
  end
  else
  begin
    // Generate stroke outline with proper line joins
    GenerateStrokeOutlineWithCaps(Points, Count, HalfWidth, LineJoin, MiterLimit, LineCap, IsClosed, LeftOutline, LeftCount, RightOutline, RightCount);

    // Render the stroke as a filled polygon
    RenderStrokePolygon(LeftOutline, LeftCount, RightOutline, RightCount);
  end;
end;

/// <summary>Generates stroke outline with proper line caps for open paths.</summary>
/// <param name="Points">Array of points defining the path centerline.</param>
/// <param name="Count">Number of points in the path.</param>
/// <param name="HalfWidth">Half the stroke width.</param>
/// <param name="LineJoin">Line join style (0=miter, 1=round, 2=bevel).</param>
/// <param name="MiterLimit">Miter limit for miter joins.</param>
/// <param name="LineCap">Line cap style for path endpoints.</param>
/// <param name="IsClosed">Whether the path should be closed.</param>
/// <param name="LeftOutline">Output array for left outline points.</param>
/// <param name="LeftCount">Number of points in left outline.</param>
/// <param name="RightOutline">Output array for right outline points.</param>
/// <param name="RightCount">Number of points in right outline.</param>
procedure TRenderer.GenerateStrokeOutlineWithCaps(const Points: array of Classes.TPoint; Count: Integer; HalfWidth: Single; LineJoin: Byte; MiterLimit: Byte; LineCap: TLineCap; IsClosed: Boolean; var LeftOutline: array of Classes.TPoint; var LeftCount: Integer; var RightOutline: array of Classes.TPoint; var RightCount: Integer);
var
  i: Integer;
  StartDX, StartDY, EndDX, EndDY, Len: Single;
  CapPoints: array[0..15] of Classes.TPoint;
  CapCount: Integer;
begin
  // First generate the main stroke outline using existing method
  GenerateStrokeOutline(Points, Count, HalfWidth, LineJoin, MiterLimit, IsClosed, LeftOutline, LeftCount, RightOutline, RightCount);

  // Add line caps for open paths
  if not IsClosed and (Count >= 2) then
  begin
    // Calculate start direction
    StartDX := Points[1].X - Points[0].X;
    StartDY := Points[1].Y - Points[0].Y;
    Len := Sqrt(StartDX * StartDX + StartDY * StartDY);
    if Len > 0.001 then
    begin
      StartDX := StartDX / Len;
      StartDY := StartDY / Len;

      // Generate start cap
      GenerateLineCap(Points[0].X, Points[0].Y, -StartDX, -StartDY, HalfWidth, LineCap, CapPoints, CapCount);

      // Insert cap points at start of outline
      if CapCount > 0 then
      begin
        // Shift existing points
        for i := LeftCount - 1 downto 0 do
        begin
          if i + CapCount < High(LeftOutline) then
          begin
            LeftOutline[i + CapCount] := LeftOutline[i];
            RightOutline[i + CapCount] := RightOutline[i];
          end;
        end;

        // Insert cap points
        for i := 0 to CapCount - 1 do
        begin
          if i < High(LeftOutline) then
          begin
            LeftOutline[i] := CapPoints[i];
            // Mirror for right outline
            RightOutline[i] := CapPoints[CapCount - 1 - i];
          end;
        end;

        Inc(LeftCount, CapCount);
        Inc(RightCount, CapCount);
      end;
    end;

    // Calculate end direction
    EndDX := Points[Count - 1].X - Points[Count - 2].X;
    EndDY := Points[Count - 1].Y - Points[Count - 2].Y;
    Len := Sqrt(EndDX * EndDX + EndDY * EndDY);
    if Len > 0.001 then
    begin
      EndDX := EndDX / Len;
      EndDY := EndDY / Len;

      // Generate end cap
      GenerateLineCap(Points[Count - 1].X, Points[Count - 1].Y, EndDX, EndDY, HalfWidth, LineCap, CapPoints, CapCount);

      // Append cap points at end of outline
      for i := 0 to CapCount - 1 do
      begin
        if LeftCount + i < High(LeftOutline) then
        begin
          LeftOutline[LeftCount + i] := CapPoints[i];
          RightOutline[RightCount + i] := CapPoints[CapCount - 1 - i];
        end;
      end;

      Inc(LeftCount, CapCount);
      Inc(RightCount, CapCount);
    end;
  end;
end;

/// <summary>Generates points for a line cap.</summary>
/// <param name="X, Y">Center point of the cap.</param>
/// <param name="DX, DY">Direction vector (normalized).</param>
/// <param name="HalfWidth">Half the stroke width.</param>
/// <param name="LineCap">Line cap style.</param>
/// <param name="CapPoints">Output array for cap points.</param>
/// <param name="CapCount">Number of points generated.</param>
procedure TRenderer.GenerateLineCap(X, Y, DX, DY: Single; HalfWidth: Single; LineCap: TLineCap; var CapPoints: array of Classes.TPoint; var CapCount: Integer);
var
  PX, PY: Single; // Perpendicular vector
  i: Integer;
  Angle: Single;
begin
  CapCount := 0;

  // Calculate perpendicular vector
  PX := -DY * HalfWidth;
  PY := DX * HalfWidth;

  case LineCap of
    TLineCap.lcButt:
    begin
      // Butt cap - just the perpendicular line
      CapPoints[0].X := Round(X + PX);
      CapPoints[0].Y := Round(Y + PY);
      CapPoints[1].X := Round(X - PX);
      CapPoints[1].Y := Round(Y - PY);
      CapCount := 2;
    end;

    TLineCap.lcRound:
    begin
      // Round cap - semicircle
      CapCount := 0;
      for i := 0 to 8 do // 9 points for semicircle
      begin
        if CapCount >= High(CapPoints) then Break;
        Angle := Pi * i / 8 - Pi / 2; // -90° to +90°
        CapPoints[CapCount].X := Round(X + HalfWidth * (DX * Cos(Angle) - DY * Sin(Angle)));
        CapPoints[CapCount].Y := Round(Y + HalfWidth * (DY * Cos(Angle) + DX * Sin(Angle)));
        Inc(CapCount);
      end;
    end;

    TLineCap.lcSquare:
    begin
      // Square cap - extends beyond the endpoint
      CapPoints[0].X := Round(X + PX + DX * HalfWidth);
      CapPoints[0].Y := Round(Y + PY + DY * HalfWidth);
      CapPoints[1].X := Round(X + PX);
      CapPoints[1].Y := Round(Y + PY);
      CapPoints[2].X := Round(X - PX);
      CapPoints[2].Y := Round(Y - PY);
      CapPoints[3].X := Round(X - PX + DX * HalfWidth);
      CapPoints[3].Y := Round(Y - PY + DY * HalfWidth);
      CapCount := 4;
    end;
  end;
end;

/// <summary>Renders a line cap at a specific point.</summary>
/// <param name="X, Y">Center point of the cap.</param>
/// <param name="DX, DY">Direction vector.</param>
/// <param name="Width">Width of the cap.</param>
/// <param name="LineCap">Line cap style.</param>
/// <param name="Color">Color to render with.</param>
procedure TRenderer.RenderLineCap(X, Y: Integer; DX, DY: Single; Width: Integer; LineCap: TLineCap; Color: TFPColor);
var
  HalfWidth: Single;
  CapPoints: array[0..15] of Classes.TPoint;
  CapCount: Integer;
  Len: Single;
begin
  HalfWidth := Width / 2.0;

  // Normalize direction if needed
  Len := Sqrt(DX * DX + DY * DY);
  if Len > 0.001 then
  begin
    DX := DX / Len;
    DY := DY / Len;
  end
  else
  begin
    DX := 1.0;
    DY := 0.0;
  end;

  GenerateLineCap(X, Y, DX, DY, HalfWidth, LineCap, CapPoints, CapCount);

  if CapCount > 0 then
    FillSolidPolygon(CapPoints, CapCount, Color);
end;

/// <summary>Determines if a point represents an actual curve or just a line point.</summary>
/// <param name="Point">The point to check.</param>
/// <returns>True if the point has different control points, indicating a curve.</returns>
function TRenderer.IsPointACurve(const Point: IcoPoint.TPoint): Boolean;
const
  EPSILON = 0.001; // Small tolerance for floating point comparison
begin
  // A point is a curve if its control points differ from its position
  // For line points: XIn = YIn = XOut = YOut = X, Y
  Result := (Abs(Point.XIn - Point.X) > EPSILON) or
            (Abs(Point.YIn - Point.Y) > EPSILON) or
            (Abs(Point.XOut - Point.X) > EPSILON) or
            (Abs(Point.YOut - Point.Y) > EPSILON);
end;

/// <summary>Flattens Bézier curves in a path to discrete points for rendering.</summary>
/// <param name="Path">The path containing curves to flatten.</param>
/// <param name="Points">Output array to store the flattened points.</param>
/// <param name="Count">Number of points generated.</param>
/// <remarks>Uses adaptive sampling based on control point distances for optimal curve quality.</remarks>
procedure TRenderer.FlattenCurvesToPoints(Path: TPath; var Points: array of Classes.TPoint; var Count: Integer);
var
  i, Steps, j: Integer;
  Point, NextPoint: IcoPoint.TPoint;
  t, oneMinusT: Single;
  X, Y: Single;
  P0X, P0Y, P1X, P1Y, P2X, P2Y, P3X, P3Y: Single;
  ControlDist: Single;
  CurrentIsCurve, NextIsCurve: Boolean;
  FlattenedPoints: array[0..4095] of record X, Y: Single; end;
  FlattenedCount, k: Integer;
begin
  Count := 0;
  if Path.GetPoints.Count = 0 then Exit;

  // Step 1: Flatten all curves in HVIF coordinate space (before transformation)
  FlattenedCount := 0;

  // Process each point in the path
  for i := 0 to Path.GetPoints.Count - 1 do
  begin
    if FlattenedCount >= High(FlattenedPoints) then Break;

    Point := Path.Points[i];
    CurrentIsCurve := IsPointACurve(Point);

    // Add the current point to flattened array
    FlattenedPoints[FlattenedCount].X := Point.X;
    FlattenedPoints[FlattenedCount].Y := Point.Y;
    Inc(FlattenedCount);

    // If there's a next point, handle the segment between current and next
    if (i < Path.GetPoints.Count - 1) and (FlattenedCount < High(FlattenedPoints) - 50) then
    begin
      NextPoint := Path.Points[i + 1];
      NextIsCurve := IsPointACurve(NextPoint);

      // Only create curve segments if either point is actually a curve
      if CurrentIsCurve or NextIsCurve then
      begin
        // Set up cubic Bezier control points in HVIF space
        P0X := Point.X;      P0Y := Point.Y;      // Start point
        P1X := Point.XOut;   P1Y := Point.YOut;   // Start control point
        P2X := NextPoint.XIn; P2Y := NextPoint.YIn; // End control point
        P3X := NextPoint.X;  P3Y := NextPoint.Y;  // End point

        // Calculate adaptive step count in HVIF coordinate space
        ControlDist := Sqrt((P1X - P0X) * (P1X - P0X) + (P1Y - P0Y) * (P1Y - P0Y)) +
                       Sqrt((P2X - P3X) * (P2X - P3X) + (P2Y - P3Y) * (P2Y - P3Y));
        Steps := Round(ControlDist * 2.0) + 5; // Adaptive sampling
        if Steps > 30 then Steps := 30; // Cap maximum steps
        if Steps < 5 then Steps := 5;   // Minimum steps

        // Sample points along the Bezier curve (skip first point, already added)
        for j := 1 to Steps - 1 do
        begin
          if FlattenedCount >= High(FlattenedPoints) then Break;

          t := j / (Steps - 1);
          oneMinusT := 1.0 - t;

          // Cubic Bezier formula: B(t) = (1-t)³P₀ + 3(1-t)²tP₁ + 3(1-t)t²P₂ + t³P₃
          X := oneMinusT * oneMinusT * oneMinusT * P0X +
               3 * oneMinusT * oneMinusT * t * P1X +
               3 * oneMinusT * t * t * P2X +
               t * t * t * P3X;

          Y := oneMinusT * oneMinusT * oneMinusT * P0Y +
               3 * oneMinusT * oneMinusT * t * P1Y +
               3 * oneMinusT * t * t * P2Y +
               t * t * t * P3Y;

          // Store flattened point in HVIF space (no transformation yet)
          FlattenedPoints[FlattenedCount].X := X;
          FlattenedPoints[FlattenedCount].Y := Y;
          Inc(FlattenedCount);
        end;
      end;
      // For line segments (both points are line points), we just connect them directly
      // The points are already added in the main loop, so no additional interpolation needed
    end;
  end;

  // Step 2: Apply transformations to all flattened points
  for k := 0 to FlattenedCount - 1 do
  begin
    if Count >= High(Points) then Break;

    X := FlattenedPoints[k].X;
    Y := FlattenedPoints[k].Y;

    // NOW apply the transformation to the flattened point
    FTransforms.TransformPoint(X, Y);
    Points[Count].X := Round(X);
    Points[Count].Y := Round(Y);
    Inc(Count);
  end;
end;



/// <summary>Creates a copy of a path with all transformation data preserved.</summary>
/// <param name="Path">The original path to copy.</param>
/// <returns>A new path object with identical point data.</returns>
/// <remarks>The actual transformation is applied during rendering, not here.</remarks>
function TRenderer.TransformPath(Path: TPath): TPath;
var
  i: Integer;
  OrigPoint, NewPoint: TObject;
begin
  Result := TPath.Create;
  Result.IsClosed := Path.IsClosed;
  Result.IsCurved := Path.IsCurved; // Preserve curve information

  // Copy all points (curve flattening will be handled during rendering)
  for i := 0 to Path.GetPoints.Count - 1 do
  begin
    OrigPoint := Path.Points[i];
    NewPoint := IcoPoint.TPoint.Create(
      (OrigPoint as IcoPoint.TPoint).X,
      (OrigPoint as IcoPoint.TPoint).Y,
      (OrigPoint as IcoPoint.TPoint).XIn,
      (OrigPoint as IcoPoint.TPoint).YIn,
      (OrigPoint as IcoPoint.TPoint).XOut,
      (OrigPoint as IcoPoint.TPoint).YOut
    );
    Result.AddPoint(NewPoint as IcoPoint.TPoint);
  end;
end;

/// <summary>Converts a style to a representative FPColor for solid rendering.</summary>
/// <param name="Style">The style to convert.</param>
/// <returns>An FPColor representing the style's color or blended gradient colors.</returns>
/// <remarks>For gradients, colors are averaged to produce a single representative color.</remarks>
function TRenderer.StyleToFPColor(Style: TStyle): TFPColor;
var
  Color: TColor;
  i: Integer;
  Step: TGradientStep;
  R, G, B, A: Integer;
begin
  if Style.HasGradient then
  begin
    // For gradients, blend the colors or use a representative color
    if Style.Gradient.GetStepCount > 0 then
    begin
      if Style.Gradient.GetStepCount = 1 then
      begin
        // Single step gradient - use that color
        Color := Style.Gradient.Steps[0].Color;
      end
      else
      begin
        // Multiple steps - blend the colors for a representative color
        R := 0; G := 0; B := 0; A := 0;
        for i := 0 to Style.Gradient.GetStepCount - 1 do
        begin
          Step := Style.Gradient.Steps[i];
          R := R + Step.Color.Red;
          G := G + Step.Color.Green;
          B := B + Step.Color.Blue;
          A := A + Step.Color.Alpha;
        end;
        // Average the colors
        R := R div Style.Gradient.GetStepCount;
        G := G div Style.Gradient.GetStepCount;
        B := B div Style.Gradient.GetStepCount;
        A := A div Style.Gradient.GetStepCount;
        Color := TColor.Create(R, G, B, A);
      end;
    end
    else
      Color := TColor.Create(128, 128, 128, 255); // Gray fallback
  end
  else
    Color := Style.Color;

  // Convert to FPColor (16-bit per channel)
  Result.Red := Color.Red shl 8 or Color.Red;
  Result.Green := Color.Green shl 8 or Color.Green;
  Result.Blue := Color.Blue shl 8 or Color.Blue;
  Result.Alpha := Color.Alpha shl 8 or Color.Alpha;
end;

/// <summary>Calculates the current render scale based on output canvas size.</summary>
/// <returns>The scale factor relative to HVIF standard size (64x64 = scale 1.0).</returns>
function TRenderer.GetRenderScale: Single;
begin
  // Calculate render scale based on output size
  // HVIF standard size is typically 64x64, so we use that as scale 1.0
  Result := Min(FWidth, FHeight) / 64.0;
end;

/// <summary>Determines if a shape should be rendered at the current scale.</summary>
/// <param name="Shape">The shape to check visibility for.</param>
/// <returns>True if the shape should be rendered based on its visibility range.</returns>
function TRenderer.ShouldRenderShape(Shape: TShape): Boolean;
var
  Scale: Single;
begin
  Scale := GetRenderScale;

  // Shape is visible if the current scale is within the min/max visibility range
  Result := (Scale >= Shape.MinVisibility) and (Scale <= Shape.MaxVisibility);
end;

/// <summary>Determines if a point is inside a polygon using ray casting algorithm.</summary>
/// <param name="X">The X coordinate to test.</param>
/// <param name="Y">The Y coordinate to test.</param>
/// <param name="Points">Array of polygon vertices.</param>
/// <param name="Count">Number of vertices in the polygon.</param>
/// <returns>True if the point is inside the polygon.</returns>
function TRenderer.IsPointInPolygon(X, Y: Integer; const Points: array of Classes.TPoint; Count: Integer): Boolean;
var
  i, j: Integer;
  xi, yi, xj, yj: Integer;
begin
  Result := False;
  if Count < 3 then Exit; // Need at least 3 points for a polygon

  j := Count - 1;
  for i := 0 to Count - 1 do
  begin
    xi := Points[i].X;
    yi := Points[i].Y;
    xj := Points[j].X;
    yj := Points[j].Y;

    // Ray casting algorithm
    if ((yi > Y) <> (yj > Y)) and
       (X < (xj - xi) * (Y - yi) / (yj - yi) + xi) then
      Result := not Result;

    j := i;
  end;
end;

/// <summary>Fills a polygon using scanline algorithm for accurate pixel-perfect rendering.</summary>
/// <param name="Points">Array of polygon vertices.</param>
/// <param name="Count">Number of vertices in the polygon.</param>
/// <param name="Style">The style to use for filling (solid color or gradient).</param>
procedure TRenderer.FillPolygonScanline(const Points: array of Classes.TPoint; Count: Integer; Style: TStyle);
var
  MinY, MaxY, Y, X: Integer;
  i, j: Integer;
  Intersections: array[0..1023] of Integer;
  IntersectionCount: Integer;
  x1, y1, x2, y2: Integer;
  Color: TFPColor;
  NormX, NormY: Single;
  GradientColor: TFPColor;
begin
  if Count < 3 then Exit;

  // Find Y bounds
  MinY := Points[0].Y;
  MaxY := Points[0].Y;
  for i := 1 to Count - 1 do
  begin
    if Points[i].Y < MinY then MinY := Points[i].Y;
    if Points[i].Y > MaxY then MaxY := Points[i].Y;
  end;

  // Clamp to canvas bounds
  if MinY < 0 then MinY := 0;
  if MaxY >= FHeight then MaxY := FHeight - 1;

  // For each scanline
  for Y := MinY to MaxY do
  begin
    // Find intersections with polygon edges
    IntersectionCount := 0;
    j := Count - 1;

    for i := 0 to Count - 1 do
    begin
      x1 := Points[j].X;
      y1 := Points[j].Y;
      x2 := Points[i].X;
      y2 := Points[i].Y;

      // Check if scanline intersects this edge
      if ((y1 > Y) <> (y2 > Y)) then
      begin
        // Calculate intersection X coordinate
        X := Round(x1 + (Y - y1) * (x2 - x1) / (y2 - y1));

        // Store intersection if within canvas bounds
        if (X >= 0) and (X < FWidth) and (IntersectionCount < High(Intersections)) then
        begin
          Intersections[IntersectionCount] := X;
          Inc(IntersectionCount);
        end;
      end;

      j := i;
    end;

    // Sort intersections
    if IntersectionCount > 1 then
    begin
      // Simple bubble sort for intersections
      for i := 0 to IntersectionCount - 2 do
        for j := i + 1 to IntersectionCount - 1 do
          if Intersections[i] > Intersections[j] then
          begin
            X := Intersections[i];
            Intersections[i] := Intersections[j];
            Intersections[j] := X;
          end;

      // Fill between pairs of intersections
      i := 0;
      while i < IntersectionCount - 1 do
      begin
        for X := Intersections[i] to Intersections[i + 1] - 1 do
        begin
          if (X >= 0) and (X < FWidth) then
          begin
            if Style.HasGradient then
            begin
              // Calculate gradient color for this pixel in world coordinates
              // Convert pixel coordinates back to HVIF coordinate space for gradient calculation
              NormX := X;
              NormY := Y;
              GradientColor := CalculateGradientColor(Style.Gradient, NormX, NormY);
              FBitmap.Colors[X, Y] := GradientColor;
            end
            else
            begin
              // Solid color fill
              Color := StyleToFPColor(Style);
              FBitmap.Colors[X, Y] := Color;
            end;
          end;
        end;
        Inc(i, 2); // Move to next pair
      end;
    end;
  end;
end;

/// <summary>Interpolates between two colors using linear interpolation.</summary>
/// <param name="Color1">The first color.</param>
/// <param name="Color2">The second color.</param>
/// <param name="t">Interpolation factor (0.0 = Color1, 1.0 = Color2).</param>
/// <returns>The interpolated color.</returns>
function TRenderer.InterpolateColor(const Color1, Color2: TColor; t: Single): TColor;
var
  OneMinusT: Single;
begin
  // Clamp t between 0 and 1
  if t < 0 then t := 0;
  if t > 1 then t := 1;

  OneMinusT := 1.0 - t;

  Result := TColor.Create(
    Round(Color1.Red * OneMinusT + Color2.Red * t),
    Round(Color1.Green * OneMinusT + Color2.Green * t),
    Round(Color1.Blue * OneMinusT + Color2.Blue * t),
    Round(Color1.Alpha * OneMinusT + Color2.Alpha * t)
  );
end;

/// <summary>Calculates the gradient color at a specific pixel coordinate.</summary>
/// <param name="Gradient">The gradient definition.</param>
/// <param name="X">The X pixel coordinate.</param>
/// <param name="Y">The Y pixel coordinate.</param>
/// <returns>The interpolated color at the specified position.</returns>
/// <remarks>Converts pixel coordinates back to the gradient's local space using matrix inversion.</remarks>
function TRenderer.CalculateGradientColor(const Gradient: TGradient; X, Y: Single): TFPColor;
var
  i: Integer;
  t: Single;
  Step1, Step2: TGradientStep;
  Color: TColor;
  Distance: Single;
  LocalX, LocalY: Single;
  FullTransform, InverseTransform: TTransformMatrix;
begin
  // Default fallback color
  Color := TColor.Create(128, 128, 128, 255);

  if Gradient.GetStepCount = 0 then
  begin
    Result.Red := Color.Red shl 8 or Color.Red;
    Result.Green := Color.Green shl 8 or Color.Green;
    Result.Blue := Color.Blue shl 8 or Color.Blue;
    Result.Alpha := Color.Alpha shl 8 or Color.Alpha;
    Exit;
  end;

  // Get the full transformation matrix (world * shape)
  FullTransform := FTransforms.GetCurrentMatrix;

  // Apply the gradient's own transform, if it exists
  if Gradient.Transformer <> nil then
    FullTransform := MultiplyMatrix(FullTransform, AffineToMatrix(Gradient.Transformer));

  // Invert the full matrix to map pixel coordinates back to the gradient's local space
  InverseTransform := InvertMatrix(FullTransform);

  // Transform the pixel's (X, Y) coordinate into the gradient's local space
  LocalX := X * InverseTransform.M11 + Y * InverseTransform.M12 + InverseTransform.M13;
  LocalY := X * InverseTransform.M21 + Y * InverseTransform.M22 + InverseTransform.M23;

  // Calculate gradient parameter 't' based on gradient type and the transformed local coordinates
  case Gradient.GradientType of
    TGradientType.Linear:
      t := (LocalY - 0.0) / 64.0; // Use Y-axis in local space for linear gradient
    TGradientType.Circular:
    begin
      Distance := Sqrt(LocalX * LocalX + LocalY * LocalY);
      t := Distance / 32.0; // Normalize by radius
    end;
    TGradientType.Diamond:
    begin
      Distance := Abs(LocalX) + Abs(LocalY);
      t := Distance / 64.0;
    end;
    TGradientType.Conic:
      t := (Pi + ArcTan2(LocalY, LocalX)) / (2 * Pi);
    TGradientType.Xy:
      t := (LocalX / 64.0 + LocalY / 64.0) / 2.0;
    TGradientType.SqrtXy:
      t := (Sqrt(Abs(LocalX/64.0)) + Sqrt(Abs(LocalY/64.0))) / 2.0;
  else
    t := 0.0; // Fallback for unknown types
  end;

  // Clamp t to the [0, 1] range
  if t < 0 then t := 0;
  if t > 1 then t := 1;

  // Convert t to gradient stop position (0-255)
  t := t * 255;

  // Find the appropriate gradient steps to interpolate between
  if Gradient.GetStepCount = 1 then
  begin
    Color := Gradient.Steps[0].Color;
  end
  else
  begin
    Step1 := Gradient.Steps[0];
    Step2 := Gradient.Steps[Gradient.GetStepCount - 1];

    for i := 0 to Gradient.GetStepCount - 2 do
    begin
      Step1 := Gradient.Steps[i];
      Step2 := Gradient.Steps[i + 1];
      if (t >= Step1.Stop) and (t <= Step2.Stop) then
        Break;
    end;

    // Interpolate between the two steps
    if Step2.Stop > Step1.Stop then
    begin
      t := (t - Step1.Stop) / (Step2.Stop - Step1.Stop);
      Color := InterpolateColor(Step1.Color, Step2.Color, t);
    end
    else
      Color := Step1.Color;
  end;

  // Convert to FPColor
  Result.Red := Color.Red shl 8 or Color.Red;
  Result.Green := Color.Green shl 8 or Color.Green;
  Result.Blue := Color.Blue shl 8 or Color.Blue;
  Result.Alpha := Color.Alpha shl 8 or Color.Alpha;
end;

/// <summary>Calculates the coverage of a pixel by a polygon for anti-aliasing.</summary>
/// <param name="X">The X coordinate of the pixel.</param>
/// <param name="Y">The Y coordinate of the pixel.</param>
/// <param name="Points">Array of polygon vertices.</param>
/// <param name="Count">Number of vertices in the polygon.</param>
/// <returns>Coverage value from 0.0 (no coverage) to 1.0 (full coverage).</returns>
/// <remarks>Uses 4x4 sub-pixel sampling for anti-aliasing calculations.</remarks>
function TRenderer.CalculatePixelCoverage(X, Y: Integer; const Points: array of Classes.TPoint; Count: Integer): Single;
var
  SubPixelSamples: Integer;
  i, j: Integer;
  SampleX, SampleY: Single;
  SamplesInside: Integer;
begin
  Result := 0.0;
  if Count < 3 then Exit;

  // Use 4x4 sub-pixel sampling for anti-aliasing
  SubPixelSamples := 4;
  SamplesInside := 0;

  for i := 0 to SubPixelSamples - 1 do
  begin
    for j := 0 to SubPixelSamples - 1 do
    begin
      // Sample at sub-pixel positions
      SampleX := X + (i + 0.5) / SubPixelSamples;
      SampleY := Y + (j + 0.5) / SubPixelSamples;

      if IsPointInPolygon(Round(SampleX), Round(SampleY), Points, Count) then
        Inc(SamplesInside);
    end;
  end;

  Result := SamplesInside / (SubPixelSamples * SubPixelSamples);
end;

/// <summary>Applies anti-aliasing to polygon edges for smoother rendering.</summary>
/// <param name="Points">Array of polygon vertices.</param>
/// <param name="Count">Number of vertices in the polygon.</param>
/// <param name="Style">The style to use for blending edge pixels.</param>
/// <remarks>Only processes pixels with partial coverage (0.0 < coverage < 1.0).</remarks>
procedure TRenderer.ApplyAntiAliasing(const Points: array of Classes.TPoint; Count: Integer; Style: TStyle);
var
  MinX, MaxX, MinY, MaxY: Integer;
  X, Y, i: Integer;
  Coverage: Single;
  FillColor, BlendedColor: TFPColor;
  CurrentColor: TFPColor;
  NormX, NormY: Single;
begin
  if Count < 3 then Exit;

  // Find bounding box
  MinX := Points[0].X; MaxX := Points[0].X;
  MinY := Points[0].Y; MaxY := Points[0].Y;

  for i := 1 to Count - 1 do
  begin
    if Points[i].X < MinX then MinX := Points[i].X;
    if Points[i].X > MaxX then MaxX := Points[i].X;
    if Points[i].Y < MinY then MinY := Points[i].Y;
    if Points[i].Y > MaxY then MaxY := Points[i].Y;
  end;

  // Extend bounds slightly for edge anti-aliasing
  Dec(MinX, 2); Dec(MinY, 2);
  Inc(MaxX, 2); Inc(MaxY, 2);

  // Clamp to canvas bounds
  if MinX < 0 then MinX := 0;
  if MinY < 0 then MinY := 0;
  if MaxX >= FWidth then MaxX := FWidth - 1;
  if MaxY >= FHeight then MaxY := FHeight - 1;


  // Apply anti-aliasing to edge pixels
  for Y := MinY to MaxY do
  begin
    for X := MinX to MaxX do
    begin
      Coverage := CalculatePixelCoverage(X, Y, Points, Count);

      if (Coverage > 0.0) and (Coverage < 1.0) then
      begin
        // This is an edge pixel - apply anti-aliasing
        if Style.HasGradient then
        begin
          // Calculate gradient color
          if MaxX > MinX then
            NormX := (X - MinX) / (MaxX - MinX)
          else
            NormX := 0.5;

          if MaxY > MinY then
            NormY := (Y - MinY) / (MaxY - MinY)
          else
            NormY := 0.5;

          FillColor := CalculateGradientColor(Style.Gradient, NormX, NormY);
        end
        else
        begin
          FillColor := StyleToFPColor(Style);
        end;

        // Get current pixel color
        CurrentColor := FBitmap.Colors[X, Y];

        // Blend fill color with current color based on coverage
        BlendedColor.Red := Round(FillColor.Red * Coverage + CurrentColor.Red * (1.0 - Coverage));
        BlendedColor.Green := Round(FillColor.Green * Coverage + CurrentColor.Green * (1.0 - Coverage));
        BlendedColor.Blue := Round(FillColor.Blue * Coverage + CurrentColor.Blue * (1.0 - Coverage));
        BlendedColor.Alpha := Round(FillColor.Alpha * Coverage + CurrentColor.Alpha * (1.0 - Coverage));

        FBitmap.Colors[X, Y] := BlendedColor;
      end;
    end;
  end;
end;

/// <summary>Fills a path with gradient colors using scanline rendering.</summary>
/// <param name="Path">The path to fill.</param>
/// <param name="Style">The style containing gradient information.</param>
/// <remarks>Transforms the path and applies both gradient filling and anti-aliasing.</remarks>
procedure TRenderer.FillPathWithGradient(Path: TPath; Style: TStyle);
var
  TransformedPath: TPath;
  TransformedPoints: array[0..1023] of Classes.TPoint;
  Count: Integer;
  i: Integer;
  Point: IcoPoint.TPoint;
  PX, PY: Single;
begin
  if Path.GetPoints.Count = 0 then Exit;

  // Transform the path
  TransformedPath := TransformPath(Path);
  try
    Count := 0;

    // Handle curved vs non-curved paths differently
    if TransformedPath.IsCurved then
    begin
      // For curved paths, flatten Bézier curves to line segments
      FlattenCurvesToPoints(TransformedPath, TransformedPoints, Count);
    end
    else
    begin
      // For non-curved paths, convert points directly to canvas coordinates
      for i := 0 to TransformedPath.GetPoints.Count - 1 do
      begin
        if Count >= High(TransformedPoints) then Break;

        Point := TransformedPath.Points[i];
        PX := Point.X;
        PY := Point.Y;

        // Apply transform stack to convert from HVIF space to pixel coordinates
        FTransforms.TransformPoint(PX, PY);

        // Store transformed point
        TransformedPoints[Count].X := Round(PX);
        TransformedPoints[Count].Y := Round(PY);
        Inc(Count);
      end;
    end;

    // Use proper scanline polygon filling with gradients
    if (Count >= 3) and TransformedPath.IsClosed then
    begin
      FillPolygonScanline(TransformedPoints, Count, Style);
      // Apply anti-aliasing for smoother edges
      ApplyAntiAliasing(TransformedPoints, Count, Style);
    end;

  finally
    TransformedPath.Free;
  end;
end;

/// <summary>Exports the rendered bitmap to PNG format without comments.</summary>
/// <param name="Buffer">Output buffer to store PNG data.</param>
procedure TRenderer.ExportToPNG(var Buffer: TBytes);
var
  EmptyText: TStringList;
begin
  EmptyText := TStringList.Create;
  try
    ExportToPNG(Buffer, EmptyText);
  finally
    EmptyText.Free;
  end;
end;

/// <summary>Exports the rendered bitmap to PNG format with a text comment.</summary>
/// <param name="Buffer">Output buffer to store PNG data.</param>
/// <param name="Text">List of text tags to add.</param>
procedure TRenderer.ExportToPNG(var Buffer: TBytes; const Text: TStringList);
var
  CustomWriter: TCustomPNGWriter;
begin
  CustomWriter := TCustomPNGWriter.Create;
  try
    // Use custom PNG writer that supports text chunks
    CustomWriter.WriteToBuffer(FBitmap, Buffer, Text);
  finally
    CustomWriter.Free;
  end;
end;

{ TCustomPNGWriter }

constructor TCustomPNGWriter.Create;
begin
  inherited Create;
  FBaseWriter := TFPWriterPNG.Create;
end;

destructor TCustomPNGWriter.Destroy;
begin
  FBaseWriter.Free;
  inherited Destroy;
end;

/// <summary>Writes a 32-bit unsigned integer in big-endian format to a stream.</summary>
/// <param name="Stream">The stream to write to.</param>
/// <param name="Value">The value to write in big-endian format.</param>
procedure TCustomPNGWriter.WriteUInt32BE(Stream: TStream; Value: Cardinal);
var
  BigEndianValue: Cardinal;
begin
  // PNG uses big-endian
  BigEndianValue := ((Value and $FF) shl 24) or
                    (((Value shr 8) and $FF) shl 16) or
                    (((Value shr 16) and $FF) shl 8) or
                    ((Value shr 24) and $FF);
  Stream.WriteBuffer(BigEndianValue, 4);
end;

/// <summary>Calculates the CRC32 checksum for PNG chunk data.</summary>
/// <param name="Data">The data to calculate CRC32 for.</param>
/// <returns>The CRC32 checksum value.</returns>
function TCustomPNGWriter.CalculateCRC32(const Data: TBytes): Cardinal;
var
  CRCTable: array[0..255] of Cardinal;
  i, j: Integer;
  CRC: Cardinal;
begin
  // Build CRC table
  for i := 0 to 255 do
  begin
    CRC := i;
    for j := 0 to 7 do
    begin
      if (CRC and 1) <> 0 then
        CRC := (CRC shr 1) xor $EDB88320
      else
        CRC := CRC shr 1;
    end;
    CRCTable[i] := CRC;
  end;

  // Calculate CRC32 for the data
  CRC := $FFFFFFFF;
  for i := 0 to Length(Data) - 1 do
    CRC := CRCTable[(CRC xor Data[i]) and $FF] xor (CRC shr 8);

  Result := CRC xor $FFFFFFFF;
end;

/// <summary>Finds the position of the IEND chunk in PNG data.</summary>
/// <param name="PNGData">The PNG data to search.</param>
/// <returns>The byte position of the IEND chunk, or -1 if not found.</returns>
function TCustomPNGWriter.FindIENDChunk(const PNGData: TBytes): Integer;
var
  i: Integer;
  IENDSignature: array[0..7] of Byte = ($00, $00, $00, $00, $49, $45, $4E, $44); // Length (0) + Type ('IEND')
begin
  Result := -1;
  // Look for IEND chunk signature
  for i := 0 to Length(PNGData) - 12 do
  begin
    if (PNGData[i] = IENDSignature[0]) and (PNGData[i+1] = IENDSignature[1]) and
       (PNGData[i+2] = IENDSignature[2]) and (PNGData[i+3] = IENDSignature[3]) and
       (PNGData[i+4] = IENDSignature[4]) and (PNGData[i+5] = IENDSignature[5]) and
       (PNGData[i+6] = IENDSignature[6]) and (PNGData[i+7] = IENDSignature[7]) then
    begin
      Result := i;
      Break;
    end;
  end;
end;

/// <summary>Adds a text chunk to PNG data before the IEND chunk.</summary>
/// <param name="PNGData">The PNG data to modify.</param>
/// <param name="Text">The text tags to add.</param>
/// <summary>Adds a text chunk to PNG data before the IEND chunk.</summary>
procedure TCustomPNGWriter.AddTextChunk(var PNGData: TBytes; const Text: TStringList);
var
  IENDPos: Integer;
  TempStream: TMemoryStream;
  ChunkType: array[0..3] of Byte = ($74, $45, $58, $74); // 'tEXt'
  ChunkData: TBytes;
  DataBytes: TBytes;
  ChunkLength: Cardinal;
  ChunkCRC: Cardinal;
  i: Integer;
  LineRB: RawByteString;
begin
  // Find the IEND chunk position
  IENDPos := FindIENDChunk(PNGData);
  if IENDPos = -1 then
    exit;

  // Nothing to add?
  if (Text = nil) or (Text.Count = 0) then
    exit;

  // Build the result in a stream for simplicity
  TempStream := TMemoryStream.Create;
  try
    // Write original data up to (but not including) IEND
    TempStream.WriteBuffer(PNGData[0], IENDPos);

    // For each serialized entry, emit a tEXt chunk
    for i := 0 to Text.Count - 1 do
    begin
      // Treat the input line as raw bytes (no transcoding)
      LineRB := RawByteString(Text[i]);
      SetLength(DataBytes, Length(LineRB));
      if Length(LineRB) > 0 then
        Move(LineRB[1], DataBytes[0], Length(LineRB));

      // Prepare chunk data
      ChunkLength := Length(DataBytes);
      SetLength(ChunkData, 4 + ChunkLength);
      Move(ChunkType[0], ChunkData[0], 4);
      if ChunkLength > 0 then
        Move(DataBytes[0], ChunkData[4], ChunkLength);

      // CRC over (type + data)
      ChunkCRC := CalculateCRC32(ChunkData);

      // Write: length (BE), type, data, CRC (BE)
      WriteUInt32BE(TempStream, ChunkLength);
      TempStream.WriteBuffer(ChunkType[0], 4);
      if ChunkLength > 0 then
        TempStream.WriteBuffer(DataBytes[0], ChunkLength);
      WriteUInt32BE(TempStream, ChunkCRC);
    end;

    // Finally, write back the original IEND chunk (12 bytes: len=0, 'IEND', CRC)
    TempStream.WriteBuffer(PNGData[IENDPos], 12);

    // Copy stream back to PNGData
    SetLength(PNGData, TempStream.Size);
    TempStream.Position := 0;
    TempStream.ReadBuffer(PNGData[0], TempStream.Size);
  finally
    TempStream.Free;
  end;
end;

/// <summary>Writes a bitmap to a PNG buffer with an optional text comment.</summary>
/// <param name="Bitmap">The bitmap image to write.</param>
/// <param name="Buffer">The output buffer to store PNG data.</param>
/// <param name="Text">The text tags to embed in the PNG.</param>
procedure TCustomPNGWriter.WriteToBuffer(Bitmap: TFPMemoryImage; var Buffer: TBytes; const Text: TStringList);
var
  Stream: TMemoryStream;
begin
  Stream := TMemoryStream.Create;
  try
    // Configure base writer settings
    FBaseWriter.Indexed := False;
    FBaseWriter.UseAlpha := True;
    FBaseWriter.WordSized := False;

    // Write PNG to memory stream using base writer
    Bitmap.SaveToStream(Stream, FBaseWriter);

    // Copy to byte array
    SetLength(Buffer, Stream.Size);
    Stream.Position := 0;
    Stream.ReadBuffer(Buffer[0], Stream.Size);

    // Add text chunk
    AddTextChunk(Buffer, Text);

  finally
    Stream.Free;
  end;
end;

end.
