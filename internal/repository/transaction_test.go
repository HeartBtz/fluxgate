package repository

import (
	"context"
	"errors"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/HeartBtz/fluxgate/internal/domain"
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestFinalizeConsumesReservationAndCreatesFileAtomically(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	file := &domain.File{ID: uuid.New(), UserID: uuid.New(), SizeBytes: 7}
	session := uuid.New()
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT id FROM users.*FOR UPDATE").WithArgs(file.UserID).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(file.UserID))
	mock.ExpectQuery("SELECT id FROM upload_sessions.*FOR UPDATE").WithArgs(session, file.UserID).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(session))
	mock.ExpectExec("DELETE FROM upload_sessions.*expires_at > clock_timestamp").WithArgs(session, file.UserID).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT id FROM users.*FOR UPDATE").WithArgs(file.UserID).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(file.UserID))
	mock.ExpectExec("UPDATE users.*SET used_bytes").WithArgs(int64(7), file.UserID).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("INSERT INTO files").WillReturnRows(sqlmock.NewRows([]string{"created", "updated"}).AddRow(time.Now(), time.Now()))
	mock.ExpectCommit()
	if err := NewFileRepository(&DB{db}).FinalizeUpload(context.Background(), file, session); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestUserDeletionChecksDataUnderOwnerLock(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	id := uuid.New()
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT role='admin'.*FOR UPDATE").WithArgs(id).WillReturnRows(sqlmock.NewRows([]string{"admin"}).AddRow(false))
	mock.ExpectQuery("SELECT EXISTS").WithArgs(id).WillReturnRows(sqlmock.NewRows([]string{"has_data"}).AddRow(true))
	mock.ExpectRollback()
	if err := NewUserRepository(&DB{db}).Delete(context.Background(), id); !errors.Is(err, domain.ErrUserHasData) {
		t.Fatalf("Delete: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestLastAdminCheckRunsInsideTransaction(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	id := uuid.New()
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT role='admin'.*FOR UPDATE").WithArgs(id).WillReturnRows(sqlmock.NewRows([]string{"admin"}).AddRow(true))
	mock.ExpectQuery("SELECT COUNT.*id<>").WithArgs(id).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectRollback()
	if err := NewUserRepository(&DB{db}).UpdateAdmin(context.Background(), &domain.User{ID: id, Role: "user"}, nil); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("UpdateAdmin: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
