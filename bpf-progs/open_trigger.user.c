#include <fcntl.h>
void main()
{
    open("/dev/null", O_RDONLY);
}
