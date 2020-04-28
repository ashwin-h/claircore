package distlock

import "context"

// Locker ensure that no two distributed processes are performing a particular action
// at the same time. this should not support recursive locking or in other words multiple
// locks by the same key are not allowed.
type Locker interface {
	// Lock must block until a mutually exclusive lock is obtained. this lock
	// acquisition must guarantee that any other process calling Lock() with the same key
	// will block. Implementer must ensure that acquiring the lock is an atomic operation
	// use a Context to timeout lock acquisition. Implementer can determine if they will return
	// an error case for Context timeout or not.
	Lock(ctx context.Context, key string) error
	// TryLock is similar to the above however will not block on lock acquisition failure.
	// if the lock was acquired TryLock must return a true and if the lock was not acquired
	// a false.
	TryLock(ctx context.Context, key string) (bool, error)
	// Unlock should return the distributed lock to the implemented synchronization point.
	Unlock(context.Context) error
}
