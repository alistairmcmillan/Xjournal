//
//  XJAppDelegate.h
//  Xjournal
//
//  Created by Fraser Speirs on Sat Jan 11 2003.
//  Copyright (c) 2003 Connected Flow. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import <OmniAppKit/OmniAppKit.h>

#import "XJHistoryWindowController.h"
#import "XJFriendsController.h"
#import "XJGlossaryWindowController.h"
#import "XJSafariBookmarkParser.h"
#import "XJBookmarksWindowController.h"
#import "XJAccountEditWindowController.h"
#import "XJPollEditorController.h"
#import "XJMainWindowController.h"

#ifdef __1.1_BUILD__
#import "XJBirthdayWindowController.h"
#import "XJShortcutController.h"
#endif

@interface XJAppDelegate : NSObject {
    /*
     These controller objects control subsidiary windows in the app.
     Because the windows are singletons, their controllers are too.
     */
    XJHistoryWindowController *histController;
    XJFriendsController *friendController;
    XJGlossaryWindowController *glossaryController;
    XJBookmarksWindowController *bookmarkController;
    XJAccountEditWindowController *accountController;
    XJPollEditorController *pollController;
    XJMainWindowController *mainController;
#ifdef __1.1_BUILD__
    XJBirthdayWindowController *birthdayController;

    XJShortcutController *shortcutController;
#endif
    
    // Connections to the progress panel
    IBOutlet NSWindow *loginPanel;
    IBOutlet NSProgressIndicator *spinner;

    // The dock menu
    NSMenu *dynDockMenu;

    // The Accounts > top level menu item
    IBOutlet NSMenuItem *accountItem;
    
    // Omni dock badge
    OADockStatusItem *dockItem;
    
    // Flag to tell us if the friends updated dialog is showing
    BOOL friendsDialogIsShowing;

    // cmd-delete menu outlets
    IBOutlet NSMenuItem *deleteFriend, *deleteFromGroup;
}

// Target for AppMenu -> Login
- (IBAction)logIn:(id)sender;

// Target for AppMenu -> Check for updates
- (IBAction)checkForUpdate:(id)sender;

// Targets for Window menu items
- (IBAction)showPrefsWindow:(id)sender;
- (IBAction)showHistoryWindow:(id)sender;
- (IBAction)showFriendsWindow:(id)sender;
- (IBAction)showGlossaryWindow:(id)sender;
- (IBAction)showBookmarkWindow:(id)sender;
- (IBAction)showPollEditWindow:(id)sender;
- (IBAction)showAccountEditWindow:(id)sender;
- (IBAction)showMainWindow:(id)sender;

// Target for Edit -> Edit Last Entry
- (IBAction) editLastEntry:(id)sender;

#ifdef __1.1_BUILD__
- (IBAction)showShortcutsWindow: (id)sender;
- (IBAction)showBirthdayWindow: (id)sender;
#endif
// Updates the dock menu with current account information
- (void)updateDockMenu;
- (void)buildAccountsMenu: (NSNotification *)note;

// Checks for (and creates if not found) the Application Support directories
- (void)checkForApplicationSupportDirs;

// Opens change notes and ReadMe
- (IBAction)openChangeNotes:(id)sender;
- (IBAction)openReadMe: (id)sender;
- (IBAction)openXjournalBlog: (id)sender;
- (IBAction)openXjournalHomePage: (id)sender;
- (IBAction)openDonate: (id)sender;

// Switching account
- (IBAction)switchAccount: (id)sender;
@end