#pragma once
//int disable_all(void);
//int update_perm(char *perm, int val);
int pledge(char *promises, char *execpromises);
int unveil(const char* path, const char* permissions);
int update_ctx(char *promises);
