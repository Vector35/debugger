#include <stdio.h>
#include <stdlib.h>

class Foo {
public:
	virtual ~Foo() {}
	virtual void bar() = 0;
};

class Bar : public Foo {
public:
	virtual void bar() {
		printf("Bar!\n");
	}
};

class Baz : public Bar {
public:
	virtual void bar() {
		printf("Baz!\n");
	}
};

int main(int ac, char **av)
{
	Foo* foo = new Baz();
	foo->bar();
	delete foo;
	return 0;
}
