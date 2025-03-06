package stateless

// TODO: maybe add this to the headers? headers.PopFirst(name)

func PopFront[T any](c []T) (T, []T, bool) {
	if len(c) == 0 {
		var zero T
		return zero, c, false
	}
	return c[0], c[1:], true
}

func PopBack[T any](c []T) (T, []T, bool) {
	if len(c) == 0 {
		var zero T
		return zero, c, false
	}
	return c[len(c)-1], c[:len(c)-1], true
}

func PushFront[T any](c []T, v T) []T {
	return append([]T{v}, c...)
}

func PushBack[T any](c []T, v T) []T {
	return append(c, v)
}
