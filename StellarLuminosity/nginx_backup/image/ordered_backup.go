package backup

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"

	"github.com/uozi-tech/cosy"
)

// createOrderedBackupArchiveToBuffer preserves the native backup member names
// while placing the objective-free nginx archive before the private UI archive.
func createOrderedBackupArchiveToBuffer(buffer *bytes.Buffer, sourceDir string) error {
	zipWriter := zip.NewWriter(buffer)
	for _, name := range []string{HashInfoFile, NginxZipName, NginxUIZipName} {
		path := filepath.Join(sourceDir, name)
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return cosy.WrapErrorWithParams(ErrCreateZipHeader, err.Error())
		}
		header.Name = name
		header.Method = zip.Deflate
		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return cosy.WrapErrorWithParams(ErrCreateZipEntry, err.Error())
		}
		file, err := os.Open(path)
		if err != nil {
			return cosy.WrapErrorWithParams(ErrOpenSourceFile, err.Error())
		}
		_, copyErr := io.Copy(writer, file)
		closeErr := file.Close()
		if copyErr != nil {
			return cosy.WrapErrorWithParams(ErrCopyContent, name)
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return zipWriter.Close()
}
