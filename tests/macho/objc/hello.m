#import <stdio.h>
#import <stdlib.h>
#import <objc/runtime.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-root-class"
#pragma clang diagnostic ignored "-Wdeprecated-objc-isa-usage"

@interface Answer
{
    Class isa;
}

+ (id)instantiate;
- (void)die;

@property(assign, nonatomic) int value;

@end

@implementation Answer

+ (id)instantiate
{
    Answer *result = malloc(class_getInstanceSize(self));
    result->isa = self;
    return result;
}

- (void)die
{
    free(self);
}

@end

#pragma clang diagnostic pop


int main(int argc, char const *argv[])
{
    Answer *answer = [Answer instantiate];
    answer.value = 42;
    printf("The answer is: %d\n", answer.value);
    [answer die];
    return 0;
}
