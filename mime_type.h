#ifndef _MIME_TYPE_H_
#define _MIME_TYPE_H_

typedef struct {
    const char *type;
    const char *string;
} mime_map;

extern mime_map mime_types[];

const char *get_mime_type_from_path(const char *path);

#endif