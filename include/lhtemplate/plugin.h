#pragma once
#pragma comment(lib, "littlehooker.lib")
#include <littlehooker/littlehooker.h>
#include <time.h>

#include "LLPreloaderAPI.h"
#include "logger.h"

bool check_ll_preloader(void);
bool init_hooks(void);
void create_plugin_dir(void);
bool load_plugin(void);
bool unload_plugin(void);
