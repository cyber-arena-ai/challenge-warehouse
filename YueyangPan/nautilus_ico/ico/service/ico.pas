{*************************************************************}
{                                                             }
{             Haiku Vector Image Format Server                }
{                                                             }
{  Copyright (c) 2025 Alexander Taylor <ajtaylor@fuzyll.com>  }
{                                                             }
{        Licensed under the Apache License, Version 2.0       }
{                                                             }
{*************************************************************}

program ico;

uses
  SysUtils,
  BaseUnix,
  Unix,
  Server in 'server.pas',
  IcoImage in 'image.pas',
  IcoPath in 'path.pas',
  IcoShape in 'shape.pas',
  IcoPoint in 'point.pas',
  IcoColor in 'color.pas',
  IcoTransformer in 'transformer.pas',
  IcoRenderer in 'renderer.pas';

var
  Port: Word;
  Server: TServer;
  ShutdownRequested: Boolean = False;

// <summary>Signal handler for graceful shutdown</summary>
// <param name="Signal">The signal number.</param>
procedure TerminateHandler(Signal: Integer); cdecl;
begin
  ShutdownRequested := True;
  WriteLn('');
  WriteLn('Shutdown signal received. Exiting gracefully...');
  if Server <> nil then
    Server.Free;
  Halt(0);
end;

// <summary>Signal handler for killing idle children</summary>
// <param name="Signal">The signal number.</param>
procedure AlarmHandler(Signal: Integer); cdecl;
begin
  ShutdownRequested := True;
  WriteLn('');
  WriteLn('Alarm timer reached. Exiting gracefully...');
  if Server <> nil then
    Server.Free;
  Halt(0);
end;

// <summary>Signal handler for preventing zombie children</summary>
// <param name="Signal">The signal number.</param>
procedure ChildHandler(Signal: Integer); cdecl;
var
  Pid: TPid;
  Status: Integer;
begin
  // Clean up all available zombie children
  repeat
    Pid := fpWaitPid(-1, @Status, WNOHANG);
  until Pid <= 0;
end;

// <summary>Installs signal handlers for graceful shutdown and preventing zombie children.</summary>
procedure InstallSignalHandlers;
var
  TermSigAction: PSigActionRec;
  IdleSigAction: PSigActionRec;
  DeadSigAction: PSigActionRec;
begin
  New(TermSigAction);
  New(IdleSigAction);
  New(DeadSigAction);

  try
    // Set up signal action handlers
    TermSigAction^.sa_handler := @TerminateHandler;
    IdleSigAction^.sa_handler := @AlarmHandler;
    DeadSigAction^.sa_handler := @ChildHandler;

    // Don't block any additional signals while these are being handled
    fpSigEmptySet(TermSigAction^.sa_mask);
    fpSigEmptySet(IdleSigAction^.sa_mask);
    fpSigEmptySet(DeadSigAction^.sa_mask);

    // Default behavior for all handlers
    TermSigAction^.sa_flags := 0;
    IdleSigAction^.sa_flags := 0;
    DeadSigAction^.sa_flags := 0;

    // Install signal handlers
    fpSigAction(SIGTERM, TermSigAction, nil);
    fpSigAction(SIGINT, TermSigAction, nil);
    fpSigAction(SIGALRM, IdleSigAction, nil);
    fpSigAction(SIGCHLD, DeadSigAction, nil);
  finally
    Dispose(TermSigAction);
    Dispose(IdleSigAction);
    Dispose(DeadSigAction);
  end;
end;

begin
  // Set up all of our special signal handlers
  InstallSignalHandlers;

  // Set the port number we will listen on
  Port := 4265;
  if GetEnvironmentVariable('PORT') <> '' Then
    Port := StrToInt(GetEnvironmentVariable('PORT'));

  // Create the server, start listening, and accept incoming connections
  Server := TServer.Create;
  try
    Server.Listen(Port);
    Server.Accept();
  finally
    Server.Free;
  end;
end.
