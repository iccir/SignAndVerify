//
//  AppDelegate.m
//  iOS Verifier
//
//  Created by Ricci Adams on 2014-07-20.
//
//

#import "AppDelegate.h"
#import "Shared.h"

@interface AppDelegate ()

@end

@implementation AppDelegate
            

- (BOOL) application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    NSString *privateKeyPath = [[NSBundle mainBundle] pathForResource:@"private_key" ofType:@"pem"];
    NSString *publicKeyPath  = [[NSBundle mainBundle] pathForResource:@"public_key"  ofType:@"pem"];
    NSString *textPath       = [[NSBundle mainBundle] pathForResource:@"input"       ofType:@"txt"];
    NSString *resultsPath    = [[NSBundle mainBundle] pathForResource:@"results"     ofType:@"txt"];

    DoTest(privateKeyPath, publicKeyPath, textPath, resultsPath);

    return YES;
}

@end
