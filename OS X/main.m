//
//  main.m
//  OS X Signer
//
//  Created by Ricci Adams on 2014-07-20.
//
//

#import <Foundation/Foundation.h>
#import "Shared.h"

int main(int argc, const char * argv[]) { @autoreleasepool
{
    if (argc != 5) {
        exit(1);
    }

    NSError  *error          = nil;
    NSString *privateKeyPath = [NSString stringWithCString:argv[1] encoding:NSUTF8StringEncoding];
    NSString *publicKeyPath  = [NSString stringWithCString:argv[2] encoding:NSUTF8StringEncoding];
    NSString *textPath       = [NSString stringWithCString:argv[3] encoding:NSUTF8StringEncoding];
    NSString *resultsPath    = [NSString stringWithCString:argv[4] encoding:NSUTF8StringEncoding];

    NSString *results = DoTest(privateKeyPath, publicKeyPath, textPath, resultsPath);
    [results writeToFile:resultsPath atomically:YES encoding:NSUTF8StringEncoding error:&error];

}
    return 0;
}
