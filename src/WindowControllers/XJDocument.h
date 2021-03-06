//
//  XJDocument.h
//  Xjournal
//
//  Created by Fraser Speirs on Sat Jan 11 2003.
//  Copyright (c) 2003 Connected Flow. All rights reserved.
//


#import <Cocoa/Cocoa.h>
#import <LJKit/LJKit.h>
#import <WebKit/WebKit.h>

#define kHTMLMenuTag 50
#define kPostMenuTag 100
#define kPostToolbarItemTag 100

#define kEditWindowToolbarIdentifier @"kEditWindowToolbarIdentifier"
#define kEditPostItemIdentifier @"kEditPostItemIdentifier"
#define kEditPostAndDiscardItemIdentifier @"kEditPostAndDiscardItemIdentifier"
#define kEditSaveItemIdentifier @"kEditSaveItemIdentifier"
#define kEditDetectMusicItemIdentifier @"kEditDetectMusicItemIdentifier"

#define kEditDrawerToggleItemIdentifier @"kEditDrawerToggleItemIdentifier"

#define kEditURLLinkItemIdentifier @"kEditURLLinkItemIdentifier"
#define kEditImageLinkItemIdentifier @"kEditImageLinkItemIdentifier"

#define kEditUserLinkItemIdentifier @"kEditUserLinkItemIdentifier"
#define kEditCommunityLinkItemIdentifier @"kEditCommunityLinkItemIdentifier"
#define kEditLJCutItemIdentifier @"kEditLJCutItemIdentifier"

#define kEditBlockquoteItemIdentifier @"kEditBlockquoteItemIdentifier"
#define kEditBoldItemIdentifier @"kEditBoldItemIdentifier"
#define kEditItalicItemIdentifier @"kEditItalicItemIdentifier"
#define kEditUnderlineItemIdentifier @"kEditUnderlineItemIdentifier"

extern NSString *TXJshowLocationField;
extern NSString *TXJshowMusicField;
extern NSString *TXJshowTagsField;
extern NSString *TXJshowMoodField;

@class XJMusic;

@interface XJDocument : NSDocument <NSToolbarDelegate>
{
    // ----------------------------------------------------------------------------------------
    // Window outlets
    // ----------------------------------------------------------------------------------------
	IBOutlet NSScrollView *theScrollView;
	IBOutlet NSTextView *theTextView;
	IBOutlet NSTextField *theSubjectField, *theMusicField, *theLocationField, *theTagField, *theMoodNameField, *statusField;
	IBOutlet NSTextField *theMusicFieldLabel, *theLocationFieldLabel, *theTagFieldLabel, *theTagPopLabel, *theMoodFieldLabel, *theMoodComboLabel, *theJournalLabel;
	IBOutlet NSButton *thePopMenuButton;
    IBOutlet NSPopUpButton *journalPop, *tagsPop;
    IBOutlet NSComboBox *moods;
    IBOutlet NSProgressIndicator *spinner;
	IBOutlet NSMenuItem *theMusicMenuItem, *theLocationMenuItem, *theTagsMenuItem, *theMoodMenuItem;
	IBOutlet NSView *fieldsView, *notFieldsView;

    // The entry associated with the window
    LJEntry *entry;
	BOOL entryHasBeenPosted; // Is entry already on LJ?
	
    // Cache thtoolbar items
    NSMutableDictionary *toolbarItemCache;

    // ----------------------------------------------------------------------------------------
    // HTML Tools Nib connections
    // ----------------------------------------------------------------------------------------
    IBOutlet NSWindow *hrefSheet, *imgSheet, *userSheet, *commSheet, *cutSheet;
    NSWindow *currentSheet;

    // ----------------------------------------------------------------------------------------
    // HTML Sheet
    // ----------------------------------------------------------------------------------------
    IBOutlet NSTextField *html_hrefField, *html_TitleField, *html_LinkTextField;
    IBOutlet NSComboBox *html_targetCombo;

    // ----------------------------------------------------------------------------------------
    // Image sheet connections
    // ----------------------------------------------------------------------------------------
    IBOutlet NSTextField *srcField, *altField, *sizeWidth, *sizeHeight, *spaceWidth, *spaceHeight, *borderSize;
    IBOutlet NSPopUpButton *alignPop;

    // ----------------------------------------------------------------------------------------
    // Community and User sheets
    // ----------------------------------------------------------------------------------------
    IBOutlet NSComboBox *comm_nameCombo, *user_nameCombo;
    IBOutlet NSButton *comm_OKButton, *user_OKButton;

    // ----------------------------------------------------------------------------------------
    // Cut sheet
    // ----------------------------------------------------------------------------------------
    IBOutlet NSTextField *cut_textField;
    IBOutlet NSTextView *cut_textView;

    // ----------------------------------------------------------------------------------------
    // Drawer
    // ----------------------------------------------------------------------------------------
    IBOutlet NSDrawer *drawer;
    IBOutlet NSPopUpButton *security, *userpic, *commentScreening;
    IBOutlet NSTableView *friendsTable;
    IBOutlet NSImageView *userPicView;
    IBOutlet NSButton *preformattedChk, *noCommentsChk, *backdatedChk, *noEmailChk;
    IBOutlet NSTextField *backdateField;

    // ----------------------------------------------------------------------------------------
    // HTML Preview
    // ----------------------------------------------------------------------------------------
    IBOutlet NSWindow *htmlPreviewWindow;
    IBOutlet WebView *htmlPreview;
	NSTimer *previewUpdateTimer;
    
    // ----------------------------------------------------------------------------------------
    // iTunes Music Store
    // ----------------------------------------------------------------------------------------
	XJMusic *currentMusic;
    
    // ----------------------------------------------------------------------------------------
    // user lookup speeding
    // ----------------------------------------------------------------------------------------
    NSArray *friendArray;
    NSArray *joinedCommunityArray;
}

- (id)initWithEntry: (LJEntry *)entry;

/* Actions for posting */
- (BOOL)postEntryAndReturnStatus;
- (void)postEntryAndDiscardLocalCopy:(id)sender;
/* Support for post confirmation dialog */
- (void)sheetDidEnd:(NSWindow *)sheet returnCode:(int)returnCode contextInfo:(void  *)contextInfo;

// Popup targets
- (IBAction)setSelectedJournal:(id)sender;
- (IBAction)setSelectedMood:(id)sender;
- (IBAction)addSelectedTag:(id)sender;

/* Builder code */
- (void)buildJournalPopup;
- (void)buildMoodPopup;
- (void)buildTagsPopup;
- (IBAction)detectMusicNow:(id)sender;

- (NSWindow *)window;
- (void)startSheet:(NSWindow *)sheet;

- (IBAction)saveWindowSize:(id)sender;

- (void)initUI;

// ----------------------------------------------------------------------------------------
// Code for selecting which textfields to show
// ----------------------------------------------------------------------------------------
- (void)moveLocationControls:(signed int)distance;
- (IBAction)musicMenuItemClicked:(id)sender;
- (IBAction)locationMenuItemClicked:(id)sender;
- (IBAction)tagsMenuItemClicked:(id)sender;
- (IBAction)moodMenuItemClicked:(id)sender;
- (void)showLocationField:(BOOL)aFlag;
- (void)showMusicField:(BOOL)aFlag;
- (void)showTagsField:(BOOL)aFlag;
- (void)showMoodField:(BOOL)aFlag;

// ----------------------------------------------------------------------------------------
// Drawer handling
// ----------------------------------------------------------------------------------------
- (IBAction)setValueForSender:(id)sender;
- (IBAction)toggleDrawer: (id)sender;

// ----------------------------------------------------------------------------------------
// HTML tools
// ----------------------------------------------------------------------------------------
- (void)genericTagWrapWithStart: (NSString *)tagStart andEnd: (NSString *)tagEnd;
- (void)insertStringAtSelection:(NSString *)newString;
- (IBAction)insertLink:(id)sender;
- (IBAction)pasteLink:(id)sender;
- (IBAction)insertImage:(id)sender;
- (IBAction)getImageDimensions:(id)sender;
- (IBAction)insertBlockquote:(id)sender;
- (IBAction)insertBold:(id)sender;
- (IBAction)insertItalic:(id)sender;
- (IBAction)insertUnderline:(id)sender;
- (IBAction)insertCenter:(id)sender;

- (IBAction)insertLJCut:(id)sender;
- (IBAction)insertLJUser:(id)sender;

- (IBAction)closeSheet:(id)sender;
- (IBAction)commitSheet:(id)sender;

// Button enablers for User and comm sheets
- (IBAction)enableOKButton:(id)sender;

// ----------------------------------------------------------------------------------------
// HTML Preview
// ----------------------------------------------------------------------------------------
- (NSWindow *)htmlPreviewWindow;
- (WebView *)htmlPreview;
- (void)updatePreviewWindow: (NSString *)textContent;
- (IBAction)showPreviewWindow: (id)sender;
- (void)closeHTMLPreviewWindow;

// =============
// Accessors
// =============
- (LJEntry *)entry;
- (void)setEntry:(LJEntry *)anEntry;

- (BOOL)entryHasBeenPosted;
- (void)setEntryHasBeenPosted:(BOOL)flag;

- (NSArray *) friendArray;
- (void) setFriendArray: (NSArray *) newFriendArray;

- (NSArray *) joinedCommunityArray;
- (void) setJoinedCommunityArray: (NSArray *) newJoinedCommunityArray;

	// Music
- (XJMusic *)currentMusic;
- (void)setCurrentMusic:(XJMusic *)aCurrentMusic;


@end
