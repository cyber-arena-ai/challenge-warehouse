{*************************************************************}
{                                                             }
{             Haiku Vector Image Format Server                }
{                                                             }
{  Copyright (c) 2025 Alexander Taylor <ajtaylor@fuzyll.com>  }
{                                                             }
{        Licensed under the Apache License, Version 2.0       }
{                                                             }
{*************************************************************}

program ico_test;

uses
  SysUtils,
  Classes,
  IcoImage in 'image.pas',
  IcoPath in 'path.pas',
  IcoShape in 'shape.pas',
  IcoPoint in 'point.pas',
  IcoColor in 'color.pas',
  IcoTransformer in 'transformer.pas',
  IcoRenderer in 'renderer.pas';

var
  FilePath, RenderPath: string;
  Icon: TImage;
  Renderer: TRenderer;
{$IFDEF DEBUG}
  Sizes: array[0..4] of Word = (16, 32, 64, 128, 256);
{$ELSE}
  Sizes: array[0..2] of Word = (16, 32, 64);
{$ENDIF}
  i: Integer;
  Text: TStringList;
  Buffer: TBytes;
  Stream: TFileStream;
begin
  ExitCode := 0;

  // Check for an argument
  if ParamCount <> 1 then
  begin
    WriteLn('Usage: ', ParamStr(0), ' <filename.hvif>');
    Halt(0);
  end;

  // Load icon from file
  FilePath := ParamStr(1);
  Icon := nil;
  WriteLn('Loading icon from ', FilePath);
  try
    Icon := TImage.Load(FilePath);
    WriteLn('Icon loaded successfully');
    WriteLn('Icon has ', Icon.GetStyleCount, ' styles');
    WriteLn('Icon has ', Icon.GetPathCount, ' paths');
    WriteLn('Icon has ', Icon.GetShapeCount, ' shapes');
  except
    on E: Exception do
    begin
      WriteLn(E.Message);
      Halt(1);
    end;
  end;

  try
    // Save icon back to file
    FilePath := Copy(FilePath, 1, Length(FilePath) - 5) + '_copy.hvif';
    WriteLn('Saving icon to ', FilePath);
    try
      Icon.Store(FilePath);
      WriteLn('Icon saved successfully');
    except
      on E: Exception do
      begin
        WriteLn('Error saving icon: ', E.Message);
        Halt(1);
      end;
    end;

    // Render icon to PNG files at various sizes
    WriteLn('Rendering icon to PNG files...');
    for i := 0 to High(Sizes) do
    begin
      RenderPath := Copy(ParamStr(1), 1, Length(ParamStr(1)) - 5) + '_' + IntToStr(Sizes[i]) + 'x' + IntToStr(Sizes[i]) + '.png';
      WriteLn('Rendering ', Sizes[i], 'x', Sizes[i], ' to ', RenderPath);
      Renderer := nil;
      try
        // Create list of comments
        Text := TStringList.Create;
        try
          Text.Add('Author' + #$00 + Icon.Author);
          if Icon.ShouldRenderComment then
            Text.Add('Comment' + #$00 + Icon.Comment);
          Text.Add('Software' + #$00 + Icon.Software);
          {$IFDEF DEBUG}
          WriteLn('Author:', Icon.Author);
          WriteLn('Comment:', Icon.Comment);
          WriteLn('Software:', Icon.Software);
          {$ENDIF}

          // Render the image
          Renderer := TRenderer.Create(Sizes[i], Sizes[i]);
          try
            Renderer.RenderImage(Icon);
            Renderer.ExportToPNG(Buffer, Text);
            if Length(Buffer) > 0 then
            begin
              Stream := TFileStream.Create(RenderPath, fmCreate);
              try
                Stream.WriteBuffer(Buffer[0], Length(Buffer));
                WriteLn('Rendered successfully (', Length(Buffer), ' bytes)');
              finally
                Stream.Free;
              end;
            end
            else
              WriteLn('Warning: Empty render buffer');
          except
            on E: Exception do
              WriteLn('Error rendering ', Sizes[i], 'x', Sizes[i], ': ', E.Message);
          end;
        finally
          Text.Free;
        end;
      finally
        if Renderer <> nil then
          Renderer.Free;
      end;
    end;

  finally
    if Icon <> nil then
      Icon.Free;
  end;
end.
