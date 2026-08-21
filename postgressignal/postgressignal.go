// Package postgressignal implements access.ChangeSignal over PostgreSQL
// LISTEN/NOTIFY, for deployments whose policy store lives in Postgres.
//
// Its sibling github.com/cccteam/access/firebasesignal serves Spanner-backed
// deployments through a Firestore document watch.
package postgressignal

import (
	"context"
	"time"

	"github.com/cccteam/access"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var _ access.ChangeSignal = &Signal{}

// watchIdleCheck is how long Watch waits quietly before pinging the
// connection, so a silently dead connection is detected even when no
// notifications arrive (writes are rare).
const watchIdleCheck = time.Minute

// Signal propagates policy-change hints through Postgres LISTEN/NOTIFY on
// the application's existing connection pool, so the signal does not
// maintain a second set of connections.
type Signal struct {
	channel    string
	listenStmt string
	pool       *pgxpool.Pool
}

// New creates a Signal on the given notification channel name. All instances
// of an app must use the same channel.
//
// Announce borrows a pooled connection. Watch acquires one connection and
// hijacks it out of the pool for the lifetime of the subscription (LISTEN
// state must never return to the pool); the pool replaces it, so while
// watching, the total connection count is the pool's plus one.
func New(pool *pgxpool.Pool, channel string) *Signal {
	return &Signal{
		channel: channel,
		// LISTEN takes an identifier, not a bind parameter, so the statement
		// is built once here with pgx's identifier quoting.
		listenStmt: "listen " + pgx.Identifier{channel}.Sanitize(),
		pool:       pool,
	}
}

// Announce broadcasts a change hint.
func (p *Signal) Announce(ctx context.Context) error {
	if _, err := p.pool.Exec(ctx, "select pg_notify($1, '')", p.channel); err != nil {
		return errors.Wrap(err, "pg_notify()")
	}

	return nil
}

// Watch listens on the channel and invokes onChange per notification until
// ctx ends. It returns on connection failure; the access Client re-invokes it
// with a delay (see access.ChangeSignal), which provides the reconnect loop.
func (p *Signal) Watch(ctx context.Context, onChange func()) error {
	pooled, err := p.pool.Acquire(ctx)
	if err != nil {
		return errors.Wrap(err, "pgxpool.Pool.Acquire()")
	}
	// Hijack removes the connection from the pool permanently: its LISTEN
	// state must never be handed to another borrower.
	conn := pooled.Hijack()
	defer closeConn(conn)

	if _, err := conn.Exec(ctx, p.listenStmt); err != nil {
		return errors.Wrap(err, "LISTEN")
	}

	for {
		waitCtx, cancel := context.WithTimeout(ctx, watchIdleCheck)
		_, err := conn.WaitForNotification(waitCtx)
		cancel()
		switch {
		case err == nil:
			onChange()
		case ctx.Err() != nil:
			return nil // clean shutdown
		case waitCtx.Err() != nil:
			// Quiet period, not a failure: confirm the connection is alive.
			if err := conn.Ping(ctx); err != nil {
				return errors.Wrap(err, "pgx.Conn.Ping()")
			}
		default:
			return errors.Wrap(err, "pgx.Conn.WaitForNotification()")
		}
	}
}

// closeConn closes with its own timeout: the caller's ctx is often already
// canceled by the time deferred cleanup runs.
func closeConn(conn *pgx.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = conn.Close(ctx)
}
