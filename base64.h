#pragma once

#include <stdio.h>
#include <stdlib.h>

void load_base64(const char *, char **, int *);
void save_base64(const char *, const char *, int);
void base64_encode(const char *, int, char **, int *);
void base64_decode(const char *, int, char **, int *);
