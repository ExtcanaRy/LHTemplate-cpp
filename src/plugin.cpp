#include <LHTemplate/plugin.h>


TLHOOK(on_initialize_logging, void,
		"?initializeLogging@DedicatedServer@@AEAAXXZ",
		uintptr_t _this)
{
	on_initialize_logging.original(_this);
	server_logger("LHTemplate Loaded!", INFO);
}

bool using_ll_preloader_api = false;

bool check_ll_preloader(void)
{
	if (GetModuleHandleA("LLPreloader.dll")) {
		puts("00:00:00 INFO [LHTemplate] The LLPreLoader is detected and is using the HookAPI it provides.");
		using_ll_preloader_api = true;
		return true;
	}
	return false;
}

bool init_hooks(void)
{
	on_initialize_logging.init(&on_initialize_logging);
	return true;
}

bool load_plugin(void)
{
	check_ll_preloader();
	if (!using_ll_preloader_api && !lh_init()) {
		puts("LittleHooker init failed");
		return false;
	}
	init_hooks();

	if (!using_ll_preloader_api)
		lh_enable_all_hook();

	return true;
}

bool unload_plugin(void)
{
	if (!using_ll_preloader_api)
		lh_uninit();
	return true;
}
