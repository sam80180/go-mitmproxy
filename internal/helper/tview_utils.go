package helper

import (
	"fmt"
	"reflect"
	"unsafe"

	tcell "github.com/gdamore/tcell/v2"
	runewidth "github.com/mattn/go-runewidth"
	"github.com/rivo/tview"
)

func TviewRemoveTrailingFormItems(form *tview.Form) {
	myIndex, _ := form.GetFocusedItemIndex()
	for i := form.GetFormItemCount() - 1; i > myIndex; i-- {
		form.RemoveFormItem(i)
	} // end for
} // end TviewRemoveTrailingFormItems()

const (
	TVIEW_INPUTFIELD_ICON_PADDING int    = 1
	TVIEW_INPUTFIELD_ICON_00      string = " "
)

var (
	TVIEW_INPUTFIELD_ICON_KO    string = "[red]✗[white]"
	TVIEW_INPUTFIELD_ICON_OK    string = "[green]✓[white]"
	TVIEW_INPUTFIELD_ICON_WIDTH int    = runewidth.StringWidth(TVIEW_INPUTFIELD_ICON_00) + (TVIEW_INPUTFIELD_ICON_PADDING * 2)
)

type tivewFormItemStatusIcon struct {
	Text       string
	Align      int
	Style      tcell.Style
	MaintainBg bool
} // end type

type MyTviewFormApplication struct {
	*tview.Application
	fullScreen          bool
	Form                *tview.Form
	formItemStatusIcons map[uintptr]tivewFormItemStatusIcon
} // end type

//go:linkname tview_printWithStyle github.com/rivo/tview.printWithStyle
func tview_printWithStyle(screen tcell.Screen, text string, x, y, skipWidth, maxWidth, align int, style tcell.Style, maintainBackground bool) (int, int, int)

func MyDefaultTviewAppCustomizer(app *tview.Application) *tview.Application {
	app.EnableMouse(true).EnablePaste(true)
	return app
} // end MyDefaultTviewAppCustomizer()

func MyDefaultTviewFormCustomizer(form *tview.Form) *tview.Form {
	form.SetBorder(true).SetTitleAlign(tview.AlignLeft)
	return form
} // end MyDefaultTviewFormCustomizer()

func NewMyTviewFormApplication(appCustomizer func(*tview.Application) *tview.Application, fullScreen bool, formCustomiser func(*tview.Form) *tview.Form) *MyTviewFormApplication {
	app := tview.NewApplication()
	if appCustomizer != nil {
		appCustomizer(app)
	} // end if
	form := tview.NewForm()
	if formCustomiser != nil {
		formCustomiser(form)
	} // end if
	myAss := MyTviewFormApplication{
		Application:         app,
		Form:                form,
		fullScreen:          fullScreen,
		formItemStatusIcons: map[uintptr]tivewFormItemStatusIcon{},
	}
	myAss.SetAfterDrawFunc(func(screen tcell.Screen) {
		for oid0, u := range myAss.formItemStatusIcons {
			isPresent := false
			for i := form.GetFormItemCount() - 1; i >= 0; i-- {
				item := form.GetFormItem(i)
				if ptr, ok := item.(*tview.InputField); ok {
					oid1 := PtrID(ptr)
					if oid0 == oid1 { // item is present in form
						isPresent = true
						break
					} // end if
				} // end if
			} // end for
			if !isPresent {
				continue
			} // end if
			f := (*tview.InputField)(unsafe.Pointer(oid0))
			x0, y0, w0, _ := f.GetRect() // get current position
			tview_printWithStyle(screen, u.Text, x0+w0-TVIEW_INPUTFIELD_ICON_WIDTH, y0, 0, TVIEW_INPUTFIELD_ICON_WIDTH, u.Align, u.Style, u.MaintainBg)
		} // end for
	})
	return &myAss
} // end NewMyTviewFormApplication()

func formatTivewFormItemStatusIcon(s string) string {
	iconFormatter := fmt.Sprintf("%%%ds%%s%%%ds", TVIEW_INPUTFIELD_ICON_PADDING, TVIEW_INPUTFIELD_ICON_PADDING)
	return fmt.Sprintf(iconFormatter, "", s, "")
} // end formatTivewFormItemStatusIcon()

func (app *MyTviewFormApplication) AddFormItem(item tview.FormItem) *tview.Form {
	app.Form.AddFormItem(item)
	return app.Form
} // end AddFormItem()

// @Override
func (app *MyTviewFormApplication) Run() error {
	return app.Application.SetRoot(app.Form, app.fullScreen).Run()
} // Run()

func (app *MyTviewFormApplication) updateStatusIcon(oid uintptr, textToCheck string, lastChar rune, accept func(textToCheck string, lastChar rune) bool) bool {
	ok := accept(textToCheck, lastChar)
	strIcon := TVIEW_INPUTFIELD_ICON_00
	if ok {
		strIcon = TVIEW_INPUTFIELD_ICON_OK
	} else {
		strIcon = TVIEW_INPUTFIELD_ICON_KO
	} // end if
	app.formItemStatusIcons[oid] = tivewFormItemStatusIcon{
		Text:       formatTivewFormItemStatusIcon(strIcon),
		Align:      tview.AlignLeft,
		Style:      tcell.StyleDefault,
		MaintainBg: true,
	}
	return ok
} // end updateStatusIcon()

func (app *MyTviewFormApplication) AddInputFieldWithStatusIcon(input *tview.InputField, accept func(textToCheck string, lastChar rune) bool, acceptInvalid bool) {
	oid := PtrID(input)
	input.SetDrawFunc(func(_ tcell.Screen, x, y, width, height int) (int, int, int, int) {
		return x, y, width - TVIEW_INPUTFIELD_ICON_WIDTH, height
	})
	oldFnInputCap := input.GetInputCapture()
	input.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if accept != nil {
			switch ev.Key() {
			// when the following keys are pressed, status is not updated. So I have to update it manually
			case tcell.KeyBackspace:
				s := input.GetText()
				if len(s) > 0 {
					s = s[0 : len(s)-1]
				} // end if
				app.updateStatusIcon(oid, s, -1, accept)
			case tcell.KeyDelete:
				rs := reflect.ValueOf(input).Elem()
				rf := rs.FieldByName("textArea")
				rf = reflect.NewAt(rf.Type(), unsafe.Pointer(rf.UnsafeAddr())).Elem()
				ta := rf.Interface().(*tview.TextArea)
				_, c0, _, _ := ta.GetCursor()
				s := input.GetText()
				if len(s) > 0 && c0 < len(s) {
					s = s[0:c0] + s[c0+1:]
				} // end if
				app.updateStatusIcon(oid, s, -1, accept)
			} // end switch
		} // end if
		if oldFnInputCap != nil {
			return oldFnInputCap(ev)
		} // end if
		return ev
	})
	input.SetAcceptanceFunc(func(textToCheck string, lastChar rune) bool {
		if accept != nil {
			ok := app.updateStatusIcon(oid, textToCheck, lastChar, accept)
			if !ok && !acceptInvalid {
				return false
			} // end if
		} // end if
		return true
	})
	app.Form.AddFormItem(input)
} // end AddInputFieldWithStatusIcon()
