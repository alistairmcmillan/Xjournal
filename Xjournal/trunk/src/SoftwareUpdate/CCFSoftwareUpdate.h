//
//  CCFSoftwareUpdate.h
//  Xjournal
//
//  Created by Fraser Speirs on Wed Jul 02 2003.
//  Copyright (c) 2003 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>


@interface CCFSoftwareUpdate : NSObject {
    // The current track dictionary from the downloaded plist
    NSDictionary *trackInfo;
    BOOL downloadIsOnReleaseTrack;
    NSTimer *updateTimer;
}
+ (CCFSoftwareUpdate *)sharedUpdateChecker;
- (void)runSoftwareUpdate:(BOOL)isScheduled;
- (void)runScheduledUpdateCheckIfRequired;
- (void)resetCheckTimer;

@end
