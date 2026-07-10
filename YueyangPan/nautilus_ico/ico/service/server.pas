{*************************************************************}
{                                                             }
{             Haiku Vector Image Format Server                }
{                                                             }
{  Copyright (c) 2025 Alexander Taylor <ajtaylor@fuzyll.com>  }
{                                                             }
{        Licensed under the Apache License, Version 2.0       }
{                                                             }
{*************************************************************}

unit Server;

interface

uses
  SysUtils,
  Classes,
  sockets,
  ctypes,
  BaseUnix,
  Unix,
  IcoImage,
  IcoColor,
  IcoPath,
  IcoShape,
  IcoPoint,
  IcoTransformer,
  IcoRenderer;

const
  UserName: AnsiString = 'ico';
  AlarmTime = $10;
  MaxImages = $10;
  MaxReadSize = $1000;

type
  // Mirror of struct passwd from <pwd.h>
  PPasswd = ^TPasswd;
  TPasswd = record
    pw_name:   PChar;
    pw_passwd: PChar;
    pw_uid:    TUID;
    pw_gid:    TGID;
    pw_gecos:  PChar;
    pw_dir:    PChar;
    pw_shell:  PChar;
  end;

  PGID = ^TGID;

  TRequestType = (
    Connect = $10,
    Disconnect = $11,
    CurrentImage = $20,
    SelectImage = $21,
    CreateImage = $22,
    DestroyImage = $23,
    LoadImage = $24,
    StoreImage = $25,
    DuplicateImage = $26,
    GetComment = $30,
    SetComment = $31,
    RenderImage = $32,
    GetStyles = $40,
    GetStyle = $41,
    SetStyle = $42,
    AddStyle = $43,
    RemoveStyle = $44,
    IsFlat = $45,
    IsTransparent = $46,
    GetColor = $47,
    SetColor = $48,
    GetGradient = $49,
    SetGradient = $4A,
    SetStep = $4B,
    AddStep = $4C,
    RemoveStep = $4D,
    GetGradientTransformer = $4E,
    SetGradientTransformer = $4F,
    GetPaths = $60,
    GetPath = $61,
    SetPath = $62,
    AddPath = $63,
    RemovePath = $64,
    GetPoint = $65,
    SetPoint = $66,
    AddPoint = $67,
    RemovePoint = $68,
    GetShapes = $80,
    GetShape = $81,
    SetShape = $82,
    AddShape = $83,
    RemoveShape = $84,
    GetShapeStyle = $85,
    SetShapeStyle = $86,
    GetShapePaths = $87,
    SetShapePaths = $88,
    AddShapePath = $89,
    RemoveShapePath = $8A,
    HasHinting = $8B,
    SetHinting = $8C,
    GetMinVisibility = $90,
    SetMinVisibility = $91,
    GetMaxVisibility = $92,
    SetMaxVisibility = $93,
    GetTransformers = $94,
    GetTransformer = $95,
    SetTransformer = $96,
    AddTransformer = $97,
    RemoveTransformer = $98
  );

  TResponseType = (
    Acknowledge = $00,
    Success = $01,
    Failure = $02,
    Result = $04
  );

  TServer = class
  private
    FImages: TList;
    FSelected: Byte;
    FServerSocket: TSocket;
    FClientSocket: TSocket;
    FConnected: Boolean;
    procedure DropPrivileges(User: AnsiString);
    procedure HandleConnection(ClientSocket: TSocket);
    procedure HandleRequests;
    function ReadSocket(Buffer: Pointer; Count: Longint): Longint;
    function WriteSocket(Buffer: Pointer; Count: Longint): Longint;
    function ReadByte: Byte;
    function ReadWord: Word;
    function GetSizedRequest: TBytes;
    procedure RespondAcknowledge;
    procedure RespondFailure;
    procedure RespondSuccess;
    procedure RespondResult(const Data: TBytes);
    procedure HandleConnect;
    procedure HandleDisconnect;
    procedure HandleCurrentImage;
    procedure HandleSelectImage;
    procedure HandleCreateImage;
    procedure HandleDestroyImage;
    procedure HandleLoadImage;
    procedure HandleStoreImage;
    procedure HandleDuplicateImage;
    procedure HandleGetComment;
    procedure HandleSetComment;
    procedure HandleRenderImage;
    procedure HandleGetStyles;
    procedure HandleGetStyle;
    procedure HandleSetStyle;
    procedure HandleAddStyle;
    procedure HandleRemoveStyle;
    procedure HandleIsFlat;
    procedure HandleIsTransparent;
    procedure HandleGetColor;
    procedure HandleSetColor;
    procedure HandleGetGradient;
    procedure HandleSetGradient;
    procedure HandleSetStep;
    procedure HandleAddStep;
    procedure HandleRemoveStep;
    procedure HandleGetGradientTransformer;
    procedure HandleSetGradientTransformer;
    procedure HandleGetPaths;
    procedure HandleGetPath;
    procedure HandleSetPath;
    procedure HandleAddPath;
    procedure HandleRemovePath;
    procedure HandleGetPoint;
    procedure HandleSetPoint;
    procedure HandleAddPoint;
    procedure HandleRemovePoint;
    procedure HandleGetShapes;
    procedure HandleGetShape;
    procedure HandleSetShape;
    procedure HandleAddShape;
    procedure HandleRemoveShape;
    procedure HandleGetShapeStyle;
    procedure HandleSetShapeStyle;
    procedure HandleGetShapePaths;
    procedure HandleSetShapePaths;
    procedure HandleAddShapePath;
    procedure HandleRemoveShapePath;
    procedure HandleHasHinting;
    procedure HandleSetHinting;
    procedure HandleGetMinVisibility;
    procedure HandleSetMinVisibility;
    procedure HandleGetMaxVisibility;
    procedure HandleSetMaxVisibility;
    procedure HandleGetTransformers;
    procedure HandleGetTransformer;
    procedure HandleSetTransformer;
    procedure HandleAddTransformer;
    procedure HandleRemoveTransformer;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Listen(const Port: Word);
    procedure Accept();
  end;

implementation

// Bind to libc functions because I couldn't get FPC to find them in the RTL or Unix units
function getpwnam(name: PChar): PPasswd; cdecl; external 'c' name 'getpwnam';
function setgroups(ngroups: SizeUInt; groups: PGID): cint; cdecl; external 'c' name 'setgroups';

{ TServer }

constructor TServer.Create;
begin
  inherited Create;
  FImages := TList.Create;
  FSelected := 0;
  FServerSocket := -1;
  FClientSocket := -1;
  FConnected := False;
end;

destructor TServer.Destroy;
var
  i: Integer;
begin
  for i := 0 to FImages.Count - 1 do
    TImage(FImages[i]).Free;
  FImages.Free;
  if FServerSocket <> -1 then
    CloseSocket(FServerSocket);
  if FClientSocket <> -1 then
    CloseSocket(FClientSocket);
  inherited Destroy;
end;

procedure TServer.DropPrivileges(User: AnsiString);
var
  Pwentry: PPasswd;
begin
  // Lookup the target user
  Pwentry := getpwnam(PChar(User));
  if Pwentry = nil then
    raise Exception.CreateFmt('Unable to find user "%s"', [User]);

  // Remove all supplemental groups
  if setgroups(0, nil) <> 0 then
    raise Exception.CreateFmt('Unable to remove extra groups (errno=%d)', [fpgeterrno]);

  // Drop GID first
  if fpSetGID(Pwentry^.pw_gid) <> 0 then
    raise Exception.CreateFmt('Unable to change GID to %d (errno=%d)', [Pwentry^.pw_gid, fpgeterrno]);

  // Then drop UID
  if fpSetUID(Pwentry^.pw_uid) <> 0 then
    raise Exception.CreateFmt('Unable to change UID to %d (errno=%d)', [Pwentry^.pw_uid, fpgeterrno]);
end;

procedure TServer.Listen(const Port: Word);
var
  Addr: TInetSockAddr;
  Opt: Integer;
begin
  // Create socket
  FServerSocket := fpSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if FServerSocket = -1 then
    raise Exception.Create('Failed to create socket.');

  // Set socket reuse option
  Opt := 1;
  if fpSetsockopt(FServerSocket, SOL_SOCKET, SO_REUSEADDR, @Opt, SizeOf(Opt)) = -1 then
    raise Exception.Create('Unable to set socket reuse option');

  // Bind to socket
  Addr.sin_family := AF_INET;
  Addr.sin_port := htons(Port);
  Addr.sin_addr.s_addr := INADDR_ANY;
  if fpBind(FServerSocket, @Addr, SizeOf(Addr)) < 0 then
    raise Exception.Create('Failed to bind socket.');

  // Listen for new connections
  if fpListen(FServerSocket, 16) = -1 then
    raise Exception.Create('Failed to listen on socket.');
end;

procedure TServer.Accept();
var
  Client: TSocket;
  pid: TPid;
begin
  while True do
  begin
    Client := fpAccept(FServerSocket, nil, nil);
    if Client = -1 then
      continue;

    // Fork a new process for each client
    pid := fpFork;
    if pid = -1 then
    begin
      // Fork failed
      WriteLn('Failed to fork in PID=', fpGetPid);
      CloseSocket(Client);
      continue;
    end
    else if pid > 0 then
    begin
      // Parent process doesn't need the client
      CloseSocket(Client);
    end
    else
    begin
      try
        // Drop privileges to the unprivileged user
        DropPrivileges(UserName);

        // Set alarm
        fpAlarm(AlarmTime);

        // Child process doesn't need the server socket
        CloseSocket(FServerSocket);

        // Handle client connection
        HandleConnection(Client);
      except
        on E: Exception do
          WriteLn('Child process ', fpGetPid, ' exception: ', E.Message);
      end;
      // Terminate process after handling client
      Halt(0);
    end;
  end;
end;

procedure TServer.HandleConnection(ClientSocket: TSocket);
begin
  FClientSocket := ClientSocket;

  try
    InitAuthorData; // See image.pas for implementation
    HandleRequests;
  except
    on E: Exception do
      WriteLn('Client error in PID ', fpGetPid, ': ', E.Message);
  end;

  // Close the client socket
  CloseSocket(FClientSocket);
  FClientSocket := -1;
end;

{ TServer Read/Write }

function TServer.ReadSocket(Buffer: Pointer; Count: Longint): Longint;
begin
  Result := fpRecv(FClientSocket, Buffer, Count, 0);
  if Result < 0 then
    raise Exception.Create('Socket read error.')
  else if Result = 0 then
    raise Exception.Create('Connection closed by client.');
end;

function TServer.WriteSocket(Buffer: Pointer; Count: Longint): Longint;
begin
  Result := fpSend(FClientSocket, Buffer, Count, 0);
  if Result <= 0 then
    raise Exception.Create('Socket write error.');
end;

function TServer.ReadByte: Byte;
begin
  ReadSocket(@Result, SizeOf(Byte));
end;

function TServer.ReadWord: Word;
begin
  ReadSocket(@Result, SizeOf(Word));
end;

function TServer.GetSizedRequest: TBytes;
var
  Size: Word;
begin
  Size := ReadWord;
  if Size > MaxReadSize then
    Size := MaxReadSize;
  SetLength(Result, Size);
  if Size > 0 then
    ReadSocket(@Result[0], Size);
end;

procedure TServer.RespondAcknowledge;
var B: Byte = Byte(TResponseType.Acknowledge);
begin WriteSocket(@B, SizeOf(B)); end;

procedure TServer.RespondFailure;
var B: Byte = Byte(TResponseType.Failure);
begin WriteSocket(@B, SizeOf(B)); end;

procedure TServer.RespondSuccess;
var B: Byte = Byte(TResponseType.Success);
begin WriteSocket(@B, SizeOf(B)); end;

procedure TServer.RespondResult(const Data: TBytes);
var
  B: Byte = Byte(TResponseType.Result);
  Size: Word;
begin
  WriteSocket(@B, SizeOf(B));
  Size := Length(Data);
  WriteSocket(@Size, SizeOf(Size));
  if Size > 0 then
    WriteSocket(@Data[0], Size);
end;

{ TSocket Handlers }

procedure TServer.HandleRequests;
var
  Request: TRequestType;
begin
  while True do
  begin
    try
      Request := TRequestType(ReadByte);
    except
      on E: Exception do
        break;
    end;

    // Don't do anything until they connect
    if not FConnected then
    begin
      if Request = TRequestType.Connect then
      begin
        HandleConnect;
        continue;
      end
      else if Request = TRequestType.Disconnect then
      begin
        HandleDisconnect;
        break;
      end
      else
        continue;
    end;

{$IFDEF DEBUG}
    WriteLn('Received request: ', Request);
{$ENDIF}

    case Request of
      TRequestType.Connect: HandleConnect;
      TRequestType.Disconnect: begin HandleDisconnect; break; end;
      TRequestType.CurrentImage: HandleCurrentImage;
      TRequestType.SelectImage: HandleSelectImage;
      TRequestType.CreateImage: HandleCreateImage;
      TRequestType.DestroyImage: HandleDestroyImage;
      TRequestType.LoadImage: HandleLoadImage;
      TRequestType.StoreImage: HandleStoreImage;
      TRequestType.DuplicateImage: HandleDuplicateImage;
      TRequestType.GetComment: HandleGetComment;
      TRequestType.SetComment: HandleSetComment;
      TRequestType.RenderImage: HandleRenderImage;
      TRequestType.GetStyles: HandleGetStyles;
      TRequestType.GetStyle: HandleGetStyle;
      TRequestType.SetStyle: HandleSetStyle;
      TRequestType.AddStyle: HandleAddStyle;
      TRequestType.RemoveStyle: HandleRemoveStyle;
      TRequestType.IsFlat: HandleIsFlat;
      TRequestType.IsTransparent: HandleIsTransparent;
      TRequestType.GetColor: HandleGetColor;
      TRequestType.SetColor: HandleSetColor;
      TRequestType.GetGradient: HandleGetGradient;
      TRequestType.SetGradient: HandleSetGradient;
      TRequestType.SetStep: HandleSetStep;
      TRequestType.AddStep: HandleAddStep;
      TRequestType.RemoveStep: HandleRemoveStep;
      TRequestType.GetGradientTransformer: HandleGetGradientTransformer;
      TRequestType.SetGradientTransformer: HandleSetGradientTransformer;
      TRequestType.GetPaths: HandleGetPaths;
      TRequestType.GetPath: HandleGetPath;
      TRequestType.SetPath: HandleSetPath;
      TRequestType.AddPath: HandleAddPath;
      TRequestType.RemovePath: HandleRemovePath;
      TRequestType.GetPoint: HandleGetPoint;
      TRequestType.SetPoint: HandleSetPoint;
      TRequestType.AddPoint: HandleAddPoint;
      TRequestType.RemovePoint: HandleRemovePoint;
      TRequestType.GetShapes: HandleGetShapes;
      TRequestType.GetShape: HandleGetShape;
      TRequestType.SetShape: HandleSetShape;
      TRequestType.AddShape: HandleAddShape;
      TRequestType.RemoveShape: HandleRemoveShape;
      TRequestType.GetShapeStyle: HandleGetShapeStyle;
      TRequestType.SetShapeStyle: HandleSetShapeStyle;
      TRequestType.GetShapePaths: HandleGetShapePaths;
      TRequestType.SetShapePaths: HandleSetShapePaths;
      TRequestType.AddShapePath: HandleAddShapePath;
      TRequestType.RemoveShapePath: HandleRemoveShapePath;
      TRequestType.HasHinting: HandleHasHinting;
      TRequestType.SetHinting: HandleSetHinting;
      TRequestType.GetMinVisibility: HandleGetMinVisibility;
      TRequestType.SetMinVisibility: HandleSetMinVisibility;
      TRequestType.GetMaxVisibility: HandleGetMaxVisibility;
      TRequestType.SetMaxVisibility: HandleSetMaxVisibility;
      TRequestType.GetTransformers: HandleGetTransformers;
      TRequestType.GetTransformer: HandleGetTransformer;
      TRequestType.SetTransformer: HandleSetTransformer;
      TRequestType.AddTransformer: HandleAddTransformer;
      TRequestType.RemoveTransformer: HandleRemoveTransformer;
    end;

    // Re-arm the alarm because we're an established connection and handling requests
    fpAlarm(AlarmTime);
  end;
end;

{ TServer Connection Handlers }

procedure TServer.HandleConnect;
begin
  FConnected := True;
  RespondAcknowledge;
end;

procedure TServer.HandleDisconnect;
begin
  FConnected := False;
  RespondAcknowledge;
end;

{ TServer Image Handlers }

procedure TServer.HandleCurrentImage;
var
  Data: TBytes;
begin
  if FSelected >= FImages.Count then
  begin
    RespondFailure;
    Exit;
  end;
  SetLength(Data, 1);
  Data[0] := FSelected;
  RespondResult(Data);
end;

procedure TServer.HandleSelectImage;
var
  IIdx: Byte;
begin
  IIdx := ReadByte;
  if IIdx < FImages.Count then
  begin
    FSelected := IIdx;
    RespondSuccess;
  end
  else
    RespondFailure;
end;

procedure TServer.HandleCreateImage;
begin
  if FImages.Count = MaxImages then
  begin
    RespondFailure;
    Exit;
  end;
  FImages.Add(TImage.Create);
  FSelected := FImages.Count - 1;
  RespondSuccess;
end;

procedure TServer.HandleDestroyImage;
var
  IIdx: Byte;
begin
  IIdx := ReadByte;
  if IIdx < FImages.Count then
  begin
    TImage(FImages[IIdx]).Free;
    FImages.Delete(IIdx);
    if (IIdx <= FSelected) and (FSelected <> 0) then
      Dec(FSelected);
    RespondSuccess;
  end
  else
    RespondFailure;
end;

procedure TServer.HandleLoadImage;
var
  Data: TBytes;
begin
  if FImages.Count = MaxImages then
  begin
    RespondFailure;
    Exit;
  end;
  Data := GetSizedRequest;
  try
    FImages.Add(TImage.Load(Data));
    FSelected := FImages.Count - 1;
    RespondSuccess;
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleStoreImage;
var
  Data: TBytes;
begin
  if FSelected >= FImages.Count then
  begin
    RespondFailure;
    Exit;
  end;
  try
    TImage(FImages[FSelected]).Store(Data);
    RespondResult(Data);
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleDuplicateImage;
var
  DuplicatedImage: TImage;
begin
  try
    if FImages.Count = MaxImages then
    begin
      RespondFailure;
      Exit;
    end;

    if FSelected >= FImages.Count then
    begin
      RespondFailure;
      Exit;
    end;

    DuplicatedImage := TImage(FImages[FSelected]).Duplicate;
    FImages.Add(DuplicatedImage);
    FSelected := FImages.Count - 1;
    RespondSuccess;
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleGetComment;
var
  Data: TBytes;
  Comment: string;
begin
  try
    if FSelected >= FImages.Count then
    begin
      RespondFailure;
      Exit;
    end;

    Comment := TImage(FImages[FSelected]).GetComment;
    SetLength(Data, Length(Comment));
    if Length(Comment) > 0 then
      Move(Comment[1], Data[0], Length(Comment));
    RespondResult(Data);
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleSetComment;
var
  Data: TBytes;
  Comment: string;
begin
  try
    if FSelected >= FImages.Count then
    begin
      RespondFailure;
      Exit;
    end;
    Data := GetSizedRequest;
    if Length(Data) > 0 then
    begin
      SetLength(Comment, Length(Data));
      Move(Data[0], Comment[1], Length(Data));
    end
    else
      Comment := '';

    TImage(FImages[FSelected]).SetComment(Comment);
    RespondSuccess;
  except
    on E: Exception do
    begin
      RespondFailure;
    end
  end;
end;

procedure TServer.HandleRenderImage;
var
  Size: Byte;
  Renderer: TRenderer;
  PngData: TBytes;
  Text: TStringList;
  Image: TImage;
begin
  // Make sure the selected image is real
  if FSelected >= FImages.Count then
  begin
    RespondFailure;
    Exit;
  end;

  try
    // Read width and height from the client
    Size := ReadByte;

    // Get the image
    Image := TImage(FImages[FSelected]);

    // Create list of comments
    Text := TStringList.Create;
    try
      Text.Add('Author' + #$00 + Image.Author);
      if Image.ShouldRenderComment then
        Text.Add('Comment' + #$00 + Image.Comment);
      Text.Add('Software' + #$00 + Image.Software);

      // Render the image
      Renderer := TRenderer.Create(Integer(Size) + 1, Integer(Size) + 1);
      try
        Renderer.RenderImage(Image);
        Renderer.ExportToPNG(PngData, Text);
        RespondResult(PngData);
      finally
        Renderer.Free;
      end;
    finally
      Text.Free;
    end;
  except
    on E: Exception do
      RespondFailure;
  end;
end;

{ TServer Style Handlers }

procedure TServer.HandleGetStyles;
var
  Data: TBytes;
begin
  try
    SetLength(Data, 1);
    Data[0] := TImage(FImages[FSelected]).GetStyleCount;
    RespondResult(Data);
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleGetStyle;
var
  SIdx: Byte;
  Data: TBytes;
begin
  SIdx := ReadByte;
  try
    Data := TImage(FImages[FSelected]).Styles[SIdx].ToBytes;
    RespondResult(Data);
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleSetStyle;
var
  Data: TBytes;
  SIdx: Byte;
  Idx: Cardinal;
  Style: TStyle;
begin
  Data := GetSizedRequest;
  try
    SIdx := Data[0];
    System.Delete(Data, 0, 1);
    Idx := 0;
    Style := TStyle.FromBytes(Data, Idx);
    TImage(FImages[FSelected]).Styles[SIdx] := Style;
    RespondSuccess;
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleAddStyle;
var
  Data: TBytes;
  Idx: Cardinal;
  Style: TStyle;
begin
  Data := GetSizedRequest;
  try
    Idx := 0;
    Style := TStyle.FromBytes(Data, Idx);
    TImage(FImages[FSelected]).AddStyle(Style);
    RespondSuccess;
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleRemoveStyle;
var
  SIdx: Byte;
begin
  SIdx := ReadByte;
  try
    TImage(FImages[FSelected]).RemoveStyle(SIdx);
    RespondSuccess;
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleIsFlat;
var
  SIdx: Byte;
  Data: TBytes;
begin
  SIdx := ReadByte;
  try
    SetLength(Data, 1);
    if not TImage(FImages[FSelected]).Styles[SIdx].HasGradient then
      Data[0] := 1
    else
      Data[0] := 0;
    RespondResult(Data);
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleIsTransparent;
var
  SIdx: Byte;
  Data: TBytes;
begin
  SIdx := ReadByte;
  try
    SetLength(Data, 1);
    if TImage(FImages[FSelected]).Styles[SIdx].HasTransparency then
      Data[0] := 1
    else
      Data[0] := 0;
    RespondResult(Data);
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleGetColor;
var
  SIdx: Byte;
  Data: TBytes;
  Style: TStyle;
begin
  SIdx := ReadByte;
  try
    Style := TImage(FImages[FSelected]).Styles[SIdx];
    if not Style.HasGradient then
    begin
      Data := Style.Color.ToBytes;
      RespondResult(Data);
    end
    else
      RespondFailure;
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleSetColor;
var
  Data: TBytes;
  SIdx: Byte;
  Idx: Cardinal;
  Color: TColor;
  Style: TStyle;
begin
  Data := GetSizedRequest;
  try
    SIdx := Data[0];
    System.Delete(Data, 0, 1);
    Idx := 0;
    Color := TColor.FromBytes(Data, Idx);
    Style := TImage(FImages[FSelected]).Styles[SIdx];
    if not Style.HasGradient then
    begin
      Style.Color := Color;
      RespondSuccess;
    end
    else
      RespondFailure;
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleGetGradient;
var
  SIdx: Byte;
  Data: TBytes;
  Style: TStyle;
begin
  SIdx := ReadByte;
  try
    Style := TImage(FImages[FSelected]).Styles[SIdx];
    if Style.HasGradient then
    begin
      Data := Style.Gradient.ToBytes;
      RespondResult(Data);
    end
    else
      RespondFailure;
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleSetGradient;
var
  Data: TBytes;
  SIdx: Byte;
  Idx: Cardinal;
  Gradient: TGradient;
  Style: TStyle;
begin
  Data := GetSizedRequest;
  try
    SIdx := Data[0];
    System.Delete(Data, 0, 1);
    Idx := 0;
    Gradient := TGradient.FromBytes(Data, Idx);
    Style := TImage(FImages[FSelected]).Styles[SIdx];
    Style.Gradient := Gradient;
    RespondSuccess;
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleSetStep;
var
  Data: TBytes;
  SIdx, GIdx: Byte;
  StepPtr: PGradientStep;
  Style: TStyle;
begin
  Data := GetSizedRequest;
  SIdx := Data[0];
  GIdx := Data[1];

  Style := TImage(FImages[FSelected]).Styles[SIdx];
  StepPtr := Style.Gradient.StepPtr[GIdx];

  StepPtr^.Stop := Data[2];
  StepPtr^.Color := TColor.Create(Data[3], Data[4], Data[5], 255);

  RespondSuccess;
end;

procedure TServer.HandleAddStep;
var
  Data: TBytes;
  SIdx, GIdx: Byte;
  Step: TGradientStep;
  Style: TStyle;
begin
  Data := GetSizedRequest;
  SIdx := Data[0];
  GIdx := Data[1];
  Step.Stop := Data[2];
  Step.Color := TColor.Create(Data[3], Data[4], Data[5], 255);

  Style := TImage(FImages[FSelected]).Styles[SIdx];
  Style.Gradient.EnsureCapacity(Style.Gradient.GetStepCount + 1);
  Style.Gradient.AddStep(Step, GIdx);
  RespondSuccess;
end;

procedure TServer.HandleRemoveStep;
var
  SIdx, GIdx: Byte;
  Style: TStyle;
begin
  SIdx := ReadByte;
  GIdx := ReadByte;
  Style := TImage(FImages[FSelected]).Styles[SIdx];
  Style.RemoveStep(GIdx);
  RespondSuccess;
end;

procedure TServer.HandleGetGradientTransformer;
var
  SIdx: Byte;
  Data: TBytes;
  Style: TStyle;
  Transformer: TAffineTransformer;
begin
  SIdx := ReadByte;
  try
    Style := TImage(FImages[FSelected]).Styles[SIdx];
    if Style.HasGradient then
    begin
      Transformer := Style.Gradient.Transformer;
      if Transformer <> nil then
      begin
        Data := Transformer.ToBytes;
        System.Delete(Data, 0, 1);
        RespondResult(Data);
      end
      else
        RespondFailure;
    end
    else
      RespondFailure;
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleSetGradientTransformer;
var
  Data: TBytes;
  SIdx: Byte;
  Idx: Cardinal;
  Transformer: TTransformer;
  Style: TStyle;
begin
  Data := GetSizedRequest;
  try
    SIdx := Data[0];
    System.Delete(Data, 0, 1);
    Idx := 0;
    Transformer := TTransformer.FromBytes(Data, Idx);
    Style := TImage(FImages[FSelected]).Styles[SIdx];
    if Style.HasGradient and (Transformer is TAffineTransformer) then
    begin
      Style.Gradient.Transformer := TAffineTransformer(Transformer);
      RespondSuccess;
    end
    else
    begin
      Transformer.Free;
      RespondFailure;
    end;
  except
    on E: Exception do
      RespondFailure;
  end;
end;

{ TServer Path Handlers }

procedure TServer.HandleGetPaths;
var
  Data: TBytes;
begin
  try
    SetLength(Data, 1);
    Data[0] := TImage(FImages[FSelected]).GetPathCount;
    RespondResult(Data);
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleGetPath;
var
  PIdx: Byte;
  Data: TBytes;
begin
  PIdx := ReadByte;
  try
    Data := TImage(FImages[FSelected]).Paths[PIdx].ToBytes;
    RespondResult(Data);
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleSetPath;
var
  Data: TBytes;
  PIdx: Byte;
  Idx: Cardinal;
  Path: TPath;
begin
  Data := GetSizedRequest;
  try
    PIdx := Data[0];
    System.Delete(Data, 0, 1);
    Idx := 0;
    Path := TPath.FromBytes(Data, Idx);
    TImage(FImages[FSelected]).Paths[PIdx] := Path;
    RespondSuccess;
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleAddPath;
var
  Data: TBytes;
  Idx: Cardinal;
  Path: TPath;
begin
  Data := GetSizedRequest;
  try
    Idx := 0;
    Path := TPath.FromBytes(Data, Idx);
    TImage(FImages[FSelected]).AddPath(Path);
    RespondSuccess;
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleRemovePath;
var
  PIdx: Byte;
begin
  PIdx := ReadByte;
  try
    TImage(FImages[FSelected]).RemovePath(PIdx);
    RespondSuccess;
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleGetPoint;
var
  PIdx, PtIdx: Byte;
  Data: TBytes;
  Path: TPath;
begin
  PIdx := ReadByte;
  PtIdx := ReadByte;
  try
    Path := TImage(FImages[FSelected]).Paths[PIdx];
    Data := Path.Points[PtIdx].ToBytes;
    RespondResult(Data);
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleSetPoint;
var
  Data: TBytes;
  PIdx, PtIdx: Byte;
  Idx: Cardinal;
  Point: TPoint;
  Path: TPath;
begin
  Data := GetSizedRequest;
  try
    PIdx := Data[0];
    System.Delete(Data, 0, 1);
    PtIdx := Data[0];
    System.Delete(Data, 0, 1);
    Idx := 0;
    Point := TPoint.FromBytes(Data, Idx);
    Path := TImage(FImages[FSelected]).Paths[PIdx];
    Path.Points[PtIdx] := Point;
    RespondSuccess;
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleAddPoint;
var
  Data: TBytes;
  PIdx, PtIdx: Byte;
  Idx: Cardinal;
  Point: TPoint;
  Path: TPath;
begin
  Data := GetSizedRequest;
  try
    PIdx := Data[0];
    System.Delete(Data, 0, 1);
    PtIdx := Data[0];
    System.Delete(Data, 0, 1);
    Idx := 0;
    Point := TPoint.FromBytes(Data, Idx);
    Path := TImage(FImages[FSelected]).Paths[PIdx];
    Path.AddPoint(Point, PtIdx);
    RespondSuccess;
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleRemovePoint;
var
  PIdx, PtIdx: Byte;
  Path: TPath;
begin
  PIdx := ReadByte;
  PtIdx := ReadByte;
  try
    Path := TImage(FImages[FSelected]).Paths[PIdx];
    Path.RemovePoint(PtIdx);
    RespondSuccess;
  except
    on E: Exception do
      RespondFailure;
  end;
end;

{ TServer Shape Handlers }

procedure TServer.HandleGetShapes;
var
  Data: TBytes;
begin
  try
    SetLength(Data, 1);
    Data[0] := TImage(FImages[FSelected]).GetShapeCount;
    RespondResult(Data);
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleGetShape;
var
  ShIdx: Byte;
  Data: TBytes;
begin
  ShIdx := ReadByte;
  try
    Data := TImage(FImages[FSelected]).Shapes[ShIdx].ToBytes;
    RespondResult(Data);
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleSetShape;
var
  Data: TBytes;
  ShIdx: Byte;
  Idx: Cardinal;
  Shape: TShape;
begin
  Data := GetSizedRequest;
  try
    ShIdx := Data[0];
    System.Delete(Data, 0, 1);
    Idx := 0;
    Shape := TShape.FromBytes(Data, Idx);
    TImage(FImages[FSelected]).Shapes[ShIdx] := Shape;
    RespondSuccess;
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleAddShape;
var
  Data: TBytes;
  Idx: Cardinal;
  Shape: TShape;
begin
  Data := GetSizedRequest;
  try
    Idx := 0;
    Shape := TShape.FromBytes(Data, Idx);
    TImage(FImages[FSelected]).AddShape(Shape);
    RespondSuccess;
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleRemoveShape;
var
  ShIdx: Byte;
begin
  ShIdx := ReadByte;
  try
    TImage(FImages[FSelected]).RemoveShape(ShIdx);
    RespondSuccess;
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleGetShapeStyle;
var
  ShIdx: Byte;
  Data: TBytes;
  Shape: TShape;
begin
  ShIdx := ReadByte;
  try
    Shape := TImage(FImages[FSelected]).Shapes[ShIdx];
    SetLength(Data, 1);
    Data[0] := Shape.Style;
    RespondResult(Data);
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleSetShapeStyle;
var
  ShIdx, SIdx: Byte;
  Shape: TShape;
begin
  ShIdx := ReadByte;
  SIdx := ReadByte;
  try
    Shape := TImage(FImages[FSelected]).Shapes[ShIdx];
    Shape.Style := SIdx;
    RespondSuccess;
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleGetShapePaths;
var
  ShIdx: Byte;
  Data: TBytes;
  Shape: TShape;
  i: Integer;
begin
  ShIdx := ReadByte;
  try
    Shape := TImage(FImages[FSelected]).Shapes[ShIdx];
    SetLength(Data, Shape.GetPathCount);
    for i := 0 to Shape.GetPathCount - 1 do
      Data[i] := Shape.Paths[i];
    RespondResult(Data);
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleSetShapePaths;
var
  Data: TBytes;
  ShIdx: Byte;
  Shape: TShape;
  i: Integer;
begin
  Data := GetSizedRequest;
  try
    ShIdx := Data[0];
    System.Delete(Data, 0, 1);
    Shape := TImage(FImages[FSelected]).Shapes[ShIdx];
    while Shape.GetPathCount > 0 do
      Shape.RemovePath(0);
    for i := 0 to Length(Data) - 1 do
      Shape.AddPath(Data[i]);
    RespondSuccess;
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleAddShapePath;
var
  ShIdx, PIdx: Byte;
  Shape: TShape;
begin
  ShIdx := ReadByte;
  PIdx := ReadByte;
  try
    Shape := TImage(FImages[FSelected]).Shapes[ShIdx];
    Shape.AddPath(PIdx);
    RespondSuccess;
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleRemoveShapePath;
var
  ShIdx, PIdx, i: Byte;
  Shape: TShape;
begin
  ShIdx := ReadByte;
  PIdx := ReadByte;
  try
    Shape := TImage(FImages[FSelected]).Shapes[ShIdx];
    for i := 0 to Shape.GetPathCount - 1 do
    begin
      if Shape.Paths[i] = PIdx then
      begin
        Shape.RemovePath(i);
        RespondSuccess;
        Exit;
      end;
    end;
    RespondFailure;
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleHasHinting;
var
  ShIdx: Byte;
  Data: TBytes;
begin
  ShIdx := ReadByte;
  try
    SetLength(Data, 1);
    if TImage(FImages[FSelected]).Shapes[ShIdx].IsHinted then
      Data[0] := 1
    else
      Data[0] := 0;
    RespondResult(Data);
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleSetHinting;
var
  ShIdx, Hint: Byte;
  Shape: TShape;
begin
  ShIdx := ReadByte;
  Hint := ReadByte;
  try
    Shape := TImage(FImages[FSelected]).Shapes[ShIdx];
    Shape.IsHinted := (Hint <> 0);
    RespondSuccess;
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleGetMinVisibility;
var
  ShIdx: Byte;
  Data: TBytes;
begin
  ShIdx := ReadByte;
  try
    SetLength(Data, 1);
    Data[0] := Round(TImage(FImages[FSelected]).Shapes[ShIdx].MinVisibility * 63.75);
    RespondResult(Data);
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleSetMinVisibility;
var
  ShIdx, Min: Byte;
  Shape: TShape;
begin
  ShIdx := ReadByte;
  Min := ReadByte;
  try
    Shape := TImage(FImages[FSelected]).Shapes[ShIdx];
    Shape.MinVisibility := Min / 63.75;
    RespondSuccess;
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleGetMaxVisibility;
var
  ShIdx: Byte;
  Data: TBytes;
begin
  ShIdx := ReadByte;
  try
    SetLength(Data, 1);
    Data[0] := Round(TImage(FImages[FSelected]).Shapes[ShIdx].MaxVisibility * 63.75);
    RespondResult(Data);
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleSetMaxVisibility;
var
  ShIdx, Max: Byte;
  Shape: TShape;
begin
  ShIdx := ReadByte;
  Max := ReadByte;
  try
    Shape := TImage(FImages[FSelected]).Shapes[ShIdx];
    Shape.MaxVisibility := Max / 63.75;
    RespondSuccess;
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleGetTransformers;
var
  ShIdx: Byte;
  Data: TBytes;
begin
  ShIdx := ReadByte;
  try
    SetLength(Data, 1);
    Data[0] := TImage(FImages[FSelected]).Shapes[ShIdx].GetTransformerCount;
    RespondResult(Data);
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleGetTransformer;
var
  ShIdx, TIdx: Byte;
  Data: TBytes;
  Shape: TShape;
begin
  ShIdx := ReadByte;
  TIdx := ReadByte;
  try
    Shape := TImage(FImages[FSelected]).Shapes[ShIdx];
    Data := Shape.Transformers[TIdx].ToBytes;
    RespondResult(Data);
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleSetTransformer;
var
  Data: TBytes;
  ShIdx, TIdx: Byte;
  Idx: Cardinal;
  Transformer: TTransformer;
  Shape: TShape;
begin
  Data := GetSizedRequest;
  try
    ShIdx := Data[0];
    System.Delete(Data, 0, 1);
    TIdx := Data[0];
    System.Delete(Data, 0, 1);
    Idx := 0;
    Transformer := TTransformer.FromBytes(Data, Idx);
    Shape := TImage(FImages[FSelected]).Shapes[ShIdx];
    Shape.Transformers[TIdx] := Transformer;
    RespondSuccess;
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleAddTransformer;
var
  Data: TBytes;
  ShIdx: Byte;
  Idx: Cardinal;
  Transformer: TTransformer;
  Shape: TShape;
begin
  Data := GetSizedRequest;
  try
    ShIdx := Data[0];
    System.Delete(Data, 0, 1);
    Idx := 0;
    Transformer := TTransformer.FromBytes(Data, Idx);
    Shape := TImage(FImages[FSelected]).Shapes[ShIdx];
    Shape.AddTransformer(Transformer);
    RespondSuccess;
  except
    on E: Exception do
      RespondFailure;
  end;
end;

procedure TServer.HandleRemoveTransformer;
var
  ShIdx, TIdx: Byte;
  Shape: TShape;
begin
  ShIdx := ReadByte;
  TIdx := ReadByte;
  try
    Shape := TImage(FImages[FSelected]).Shapes[ShIdx];
    Shape.RemoveTransformer(TIdx);
    RespondSuccess;
  except
    on E: Exception do
      RespondFailure;
  end;
end;

end.
