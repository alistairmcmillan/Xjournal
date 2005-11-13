//
//  KeyHandlingTableView.m
//  Xjournal
//
//  Created by Fraser Speirs on Thu Apr 17 2003.
//  Copyright (c) 2003 Connected Flow. All rights reserved.
//

#import "KeyHandlingTableView.h"


@implementation KeyHandlingTableView

/*
 * This category overrides -keyDown to provide an additional delegate 
 * method for when the user presses delete on the table.
 */
- (void)keyDown:(NSEvent *)event {
    
    unichar key = [[event charactersIgnoringModifiers] characterAtIndex:0];
    unsigned int flags = [event modifierFlags];

    if (key == NSDeleteCharacter &&
        flags == 0 &&
        [self numberOfRows] > 0 &&
        [self selectedRow] != -1) {
        
        if([[self delegate] respondsToSelector:@selector(handleDeleteKeyInTableView:)])
            [[self delegate] handleDeleteKeyInTableView: self];
    }

	[super keyDown:event]; // let somebody else handle the event
}
@end