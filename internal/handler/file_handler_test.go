package handler

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"strings"
	"testing"
)

func TestStreamMultipartFileSkipsFieldsAndStreamsFile(t *testing.T) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("description", "before the file"); err != nil {
		t.Fatal(err)
	}
	part, err := mw.CreateFormFile("file", "large.iso")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("streamed payload")); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}

	mediaType, params, err := mime.ParseMediaType(mw.FormDataContentType())
	if err != nil {
		t.Fatal(err)
	}
	file, err := streamMultipartFile(mediaType, params, &body)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	got, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	if file.FileName() != "large.iso" || string(got) != "streamed payload" {
		t.Fatalf("file = %q, payload = %q", file.FileName(), got)
	}
}

func TestMultipartPreambleIsBounded(t *testing.T) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("padding", strings.Repeat("x", 2<<20)); err != nil {
		t.Fatal(err)
	}
	part, err := mw.CreateFormFile("file", "test.txt")
	if err != nil {
		t.Fatal(err)
	}
	part.Write([]byte("file"))
	mw.Close()
	mediaType, params, _ := mime.ParseMediaType(mw.FormDataContentType())
	if _, err := streamMultipartFile(mediaType, params, &body); err == nil {
		t.Fatal("oversized preamble accepted")
	}
	if body.Len() < 1<<20 {
		t.Fatal("oversized preamble drained")
	}
}
