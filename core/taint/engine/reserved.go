package engine

import "strings"

// Reserved words per language.
//
// isKeyword is one list for every language: the union of Python, JavaScript,
// Ruby, Rust, C#, Swift, Perl, Lua, Dart and Elixir keywords plus common type
// names. As a filter on VARIABLE names that union is wrong in every language
// it is not the keyword of: a Python variable named `type`, `match`, `string`,
// `default` or `object`, a JavaScript `get` or `set`, a Java `data`-holding
// `var` named `open` or `any` was dropped as a keyword, and with it every read
// and assignment of the value. Found on the NIST SARD PHP suite, where
// `$string = $_POST[...]; unserialize($string)` reported nothing.
//
// The two decisions that say what a variable is -- the names an expression
// reads (freeIdentifiers) and the name an assignment binds (splitAssignment)
// -- use the language's own reserved words. Everything else keeps isKeyword:
// header and declaration parsers use it to skip modifiers and types, where
// the union is harmless.
//
// A reserved word treated as a variable costs nothing -- it is never assigned
// a value, so it is never tainted -- so each set lists the language's actual
// reserved words and literals, not its contextual keywords or type names.
// `self` and `this` stay excluded everywhere, as they were.

var reservedWords = map[langKind]map[string]bool{
	langPython: words(`False None True and as assert async await break class continue def del elif else
		except finally for from global if import in is lambda nonlocal not or pass raise return try
		while with yield self`),
	langJavaScript: words(`break case catch class const continue debugger default delete do else enum export
		extends false finally for function if import in instanceof new null return super switch this
		throw true try typeof var void while with yield let static await undefined`),
	langPHP: words(`abstract and array as break callable case catch class clone const continue declare
		default do echo else elseif empty enddeclare endfor endforeach endif endswitch endwhile eval
		exit extends final finally fn for foreach function global goto if implements include
		include_once instanceof insteadof interface isset list match namespace new or print private
		protected public readonly require require_once return static switch throw trait try unset use
		var while xor yield true false null this self parent`),
	langJava: words(`abstract assert boolean break byte case catch char class const continue default do
		double else enum extends final finally float for goto if implements import instanceof int
		interface long native new package private protected public return short static strictfp super
		switch synchronized this throw throws transient try void volatile while true false null var`),
	langCSharp: words(`abstract as base bool break byte case catch char checked class const continue
		decimal default delegate do double else enum event explicit extern false finally fixed float
		for foreach goto if implicit in int interface internal is lock long namespace new null object
		operator out override params private protected public readonly ref return sbyte sealed short
		sizeof stackalloc static string struct switch this throw true try typeof uint ulong unchecked
		unsafe ushort using virtual void volatile while var`),
	langRuby: words(`BEGIN END alias and begin break case class def defined do else elsif end ensure
		false for if in module next nil not or redo rescue retry return self super then true undef
		unless until when while yield __FILE__ __LINE__`),
	langRust: words(`as async await break const continue crate dyn else enum extern false fn for if impl
		in let loop match mod move mut pub ref return self Self static struct super trait true type
		unsafe use where while`),
	langKotlin: words(`as break class continue do else false for fun if in interface is null object
		package return super this throw true try typealias typeof val var when while`),
	langScala: words(`abstract case catch class def do else extends false final finally for forSome if
		implicit import lazy match new null object override package private protected return sealed
		super this throw trait try true type val var while with yield`),
	langSwift: words(`associatedtype class deinit enum extension fileprivate func import init inout
		internal let open operator private protocol public rethrows static struct subscript typealias
		var break case continue default defer do else fallthrough for guard if in repeat return switch
		where while as catch false is nil super self Self throw throws true try`),
	langGroovy: words(`abstract as assert boolean break byte case catch char class const continue def
		default do double else enum extends false final finally float for goto if implements import in
		instanceof int interface long native new null package private protected public return short
		static super switch synchronized this throw throws trait transient true try void volatile while`),
	langDart: words(`abstract as assert async await break case catch class const continue covariant
		default deferred do dynamic else enum export extends extension external factory false final
		finally for if implements import in is late library mixin new null operator part required
		rethrow return static super switch sync this throw true try typedef var void while with yield`),
	langCPP: words(`alignas alignof and asm auto bool break case catch char class const constexpr
		const_cast continue decltype default delete do double dynamic_cast else enum explicit export
		extern false float for friend goto if inline int long mutable namespace new noexcept not
		nullptr operator or private protected public register reinterpret_cast return short signed
		sizeof static static_assert static_cast struct switch template this throw true try typedef
		typeid typename union unsigned using virtual void volatile while NULL`),
	langPerl: words(`my our local sub package use no require if elsif else unless while until for
		foreach do last next redo return and or not eq ne lt gt le ge cmp qw undef wantarray`),
	langLua: words(`and break do else elseif end false for function goto if in local nil not or repeat
		return then true until while self`),
	langElixir: words(`true false nil when and or not in fn do end catch rescue after else def defp
		defmodule defmacro defmacrop defstruct defprotocol defimpl case cond receive quote unquote
		alias require import use with for raise try`),
}

func words(s string) map[string]bool {
	out := map[string]bool{"this": true, "self": true}
	for _, w := range strings.Fields(s) {
		out[w] = true
	}
	return out
}

// isReservedIn reports whether s is a reserved word of lang. A language with
// no set here keeps the shared list.
func isReservedIn(lang langKind, s string) bool {
	if set, ok := reservedWords[lang]; ok {
		return set[s]
	}
	return isKeyword(s)
}

// isSimpleIdentIn is isSimpleIdent with lang's reserved words.
func isSimpleIdentIn(lang langKind, s string) bool {
	if s == "" || !isIdentStart(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !isIdentPart(s[i]) {
			return false
		}
	}
	return !isReservedIn(lang, s)
}
