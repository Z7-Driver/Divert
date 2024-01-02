#pragma once
#include "blog_instance.h"
#include "blog_manager.h"
#include "blog_def.h"


#if defined(BLOG)
#undef BLOG
#endif

#define BLOG(level)\
	blog::BLogInstance((int)blog::BLogLevel::##level, __LINE__, __FILEW__, false).GetInputUTF8()

#define BLOGW(level)\
	blog::BLogInstance((int)blog::BLogLevel::##level, __LINE__, __FILEW__, true).GetInputUTF16()

/*
* FATAL : 0
* ERROR : 1
* WARNING : 2
* INFO : 3
* OTHER : 4 5 6 7 8 9 10 .....
*/
#define BLOG_LEVEL(level)\
	blog::BLogInstance(level, __LINE__, __FILEW__, false).GetInputUTF8()

/*
* FATAL : 0
* ERROR : 1
* WARNING : 2
* INFO : 3
* OTHER : 4 5 6 7 8 9 10 .....
*/
#define BLOG_LEVELW(level)\
	blog::BLogInstance(level, __LINE__, __FILEW__, true).GetInputUTF16()
