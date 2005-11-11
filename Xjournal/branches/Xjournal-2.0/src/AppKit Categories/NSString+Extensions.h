/*
 * $Id: NSString+Extensions.h,v 1.1.1.1 2004/08/05 21:21:47 fspeirs Exp $
 *
 * Copyright (c) 2001, 2002 William J. Coldwell
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 *  * Neither the name of the author nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */


#import <Cocoa/Cocoa.h>

@interface NSString (WhiteSpaceExt) 
- (NSString *)stringByRemovingSurroundingWhitespace;
@end

@interface NSString (ContainsString)
- (BOOL) containsString:(NSString *)myString;
@end

// Added by koliver for encoding of unicode chars
@interface NSString (HtmlCodec)
- (NSString *) encodeAsHtml;
- (NSString *) decodeHtml;

// Moved from a bad place by gnarf37
- (NSString *) urlEncode:(BOOL) useUTF8;
- (NSString *) urlEncodeASCII;
- (NSString *) urlDecode:(BOOL) useUTF8;
- (NSString *) urlDecodeASCII;
@end

@interface NSString (LJCutConversions)
- (NSString *)translateNewLines;
- (NSString *)translateLJUser;
- (NSString *)translateLJComm;
//- (NSString *)translateLJCutBlockWithItemURL: (NSString *)url;
//- (NSString *)translateLJStandaloneCutWithItemURL: (NSString *)url;
- (NSString *)translateLJCutOpenTagWithText;
- (NSString *)translateBasicLJCutOpenTag;
- (NSString *)translateLJCutCloseTag;
- (NSString *)translateLJPoll;
- (NSString *)translateLJPhonePostWithItemURL:(NSString *)url userName: (NSString *)user;
@end

// Moved from NSString+extras.h from Ranchero.com's RSS class
@interface NSString (extras)
- (NSString *) trimWhiteSpace;
- (NSString *) stripHTML;
- (NSString *) ellipsizeAfterNWords: (int) n;
+ (BOOL) stringIsEmpty: (NSString *) s;
@end

@interface NSString (Technorati)
- (NSString *)technoratiTags;
@end