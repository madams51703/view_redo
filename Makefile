CC=gcc
CFLAGS=-I.
DEPS =
OBJ = view_redo.c

%.o: %.c $(DEPS)
        $(CC) -c -o $@ $< $(CFLAGS)

view_redo: $(OBJ)
        $(CC) -o $@ $^ $(CFLAGS)
