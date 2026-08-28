import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideZonelessChangeDetection } from '@angular/core';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';

import { appConfig } from '../app.config';
import { MatCardModule } from '@angular/material/card';

/**
 * A host for the Material components whose appearance depends on a global stylesheet.
 *
 * Both specs below read a computed style rather than a class list, because in both cases the markup
 * was correct all along and no rule matched it. An assertion about the DOM would have passed while
 * the application rendered the word "notifications" across its own toolbar.
 */
@Component({
  selector: 'farrier-material-styles-probe',
  imports: [MatCardModule, MatFormFieldModule, MatIconModule, MatInputModule],
  template: `
    <mat-icon>notifications</mat-icon>
    <mat-form-field appearance="outline" style="width: 12rem">
      <mat-label>Bearer token</mat-label>
      <input matInput />
      <mat-hint>
        A hint long enough to wrap onto several lines in a field this narrow, which is the case that
        used to write over whatever sat beneath it. Every hint in this application is a sentence
        explaining what a field is for, so this is the ordinary case rather than an extreme one.
      </mat-hint>
    </mat-form-field>
    <mat-card>
      <mat-card-content class="flex flex-col gap-4">
        <span>first</span>
        <span>second</span>
      </mat-card-content>
    </mat-card>
  `,
})
class Probe {}

/** Renders the probe and returns its root element, attached to the document so styles resolve. */
function render(): HTMLElement {
  TestBed.configureTestingModule({
    imports: [Probe],
    // The application's own providers, not a stand-in list. One of the specs below is about
    // MAT_FORM_FIELD_DEFAULT_OPTIONS, which is configured in appConfig and nowhere else — a spec that
    // rebuilt the provider list would assert its own copy and pass with the real one removed.
    providers: [provideZonelessChangeDetection(), ...appConfig.providers],
  });
  const fixture = TestBed.createComponent(Probe);
  fixture.detectChanges();
  return fixture.nativeElement as HTMLElement;
}

/**
 * Every rule this application's own stylesheet writes for the notched outline.
 *
 * Material's own rules are excluded by looking only for a rule that sets a border style to `none`,
 * which is the shape of the fix rather than of anything upstream ships. A stylesheet whose rules cannot
 * be read is skipped: karma serves these same-origin, and a browser that refused would otherwise fail
 * this spec for a reason having nothing to do with the seam.
 */
function ourNotchRules(): CSSStyleRule[] {
  return styleRules()
    .filter((rule): rule is CSSStyleRule => rule instanceof CSSStyleRule)
    .filter((rule) => rule.selectorText.includes('.mdc-notched-outline__notch'))
    .filter((rule) => rule.cssText.includes('style: none') || rule.cssText.includes('style:none'));
}

/**
 * Every rule in every stylesheet the document has, flattened.
 *
 * A stylesheet whose rules cannot be read is skipped rather than failing the caller: karma serves
 * these same-origin, and a browser that refused would otherwise fail a spec for a reason having
 * nothing to do with what it is about.
 */
function styleRules(): CSSRule[] {
  const all: CSSRule[] = [];
  for (const sheet of Array.from(document.styleSheets)) {
    try {
      all.push(...Array.from(sheet.cssRules));
    } catch {
      continue;
    }
  }
  return all;
}

describe('the global stylesheet, where it meets Angular Material', () => {
  it('gives mat-icon the bundled icon font, so a ligature name renders as a glyph', () => {
    const icon = render().querySelector('mat-icon');
    expect(icon).not.toBeNull();

    // @fontsource ships the @font-face and not the class that uses it. Without src/styles.scss
    // supplying that half, this is whatever body is set in — and every icon in the application is
    // its own name in words.
    const style = getComputedStyle(icon as Element);
    expect(style.fontFamily).toContain('Material Icons');
    expect(style.fontFeatureSettings).toContain('liga');
  });

  it('has the bundled @font-face the rule names, not only the rule', () => {
    // The spec above proves the rule applies. It cannot notice the other half of the same failure:
    // drop @fontsource/material-icons from angular.json and the declared family is still "Material
    // Icons", the computed style is unchanged, and every icon renders as its own name again — which is
    // exactly what the issue reported. The two halves have to be bundled together or neither works,
    // and they are listed in two different files.
    //
    // The declaration is asserted rather than the loaded face. Whether a browser has fetched a
    // font by the time a spec runs is a question about the test server, and a spec that answered it
    // would fail for reasons having nothing to do with the bundle.
    const faces = styleRules()
      .filter((rule): rule is CSSFontFaceRule => rule instanceof CSSFontFaceRule)
      .filter((rule) => rule.style.getPropertyValue('font-family').includes('Material Icons'));

    expect(faces.length)
      .withContext(
        'no @font-face declares Material Icons. It comes from @fontsource/material-icons, listed in ' +
          "angular.json; without it the class in styles.scss names a family the browser does not have.",
      )
      .toBeGreaterThan(0);
  });

  it('draws no border down the middle of an outlined field', () => {
    const notch = render().querySelector('.mdc-notched-outline__notch');
    expect(notch).not.toBeNull();

    // Material leaves this side at the browser default of `border-style: none` and sets a width on
    // all four sides, which is harmless until Tailwind's Preflight sets `border: 0 solid` globally
    // and gives the width something to draw: a full-height rule through the middle of the field.
    const style = getComputedStyle(notch as Element);
    expect(style.borderInlineEndStyle).toBe('none');
    expect(style.borderInlineEndWidth).toBe('0px');
  });

  it('names the seam by its logical side, so the line does not come back in right-to-left', () => {
    // This one reads the rule rather than the render, and the reason is that the render cannot tell
    // the difference. Material mirrors which side carries the transparent seam with a [dir=rtl] rule,
    // so a fix written as `border-right-style: none` computes identically to the correct one in the
    // default direction — the spec above passes either way — and draws the line again in Arabic and
    // Hebrew. What separates them is which property was written, so that is what is asserted.
    const ours = ourNotchRules();
    expect(ours.length)
      .withContext('no stylesheet rule targets .mdc-notched-outline__notch any more')
      .toBeGreaterThan(0);

    for (const rule of ours) {
      expect(rule.style.getPropertyValue('border-inline-end-style'))
        .withContext(rule.cssText)
        .toBe('none');
      for (const physical of ['border-right-style', 'border-left-style']) {
        expect(rule.style.getPropertyValue(physical))
          .withContext(`${rule.cssText}\nA physical side is the wrong side in one of the two writing directions.`)
          .toBe('');
      }
    }
  });

  it('lets a Tailwind layout utility beat the Material rule it collides with', () => {
    const content = render().querySelector('.mat-mdc-card-content');
    expect(content).not.toBeNull();

    // Tailwind puts its utilities in `@layer utilities`, and Material injects a component's styles as
    // an unlayered <style> element when the component first loads — and an unlayered rule beats a
    // layered one whatever its specificity and whatever the order. So `.mat-mdc-card-content { display:
    // block }` silently won against `flex`, and every card in the application laid its contents out
    // wrongly: fields side by side, hints over the content beneath them. `@import "tailwindcss"
    // important` is what restores the division of labour, and this is what notices if it is removed.
    expect(getComputedStyle(content as Element).display).toBe('flex');
  });

  it('gives a wrapped hint room, so it does not write over the next field', () => {
    const hint = render().querySelector('.mat-mdc-form-field-hint-wrapper');
    expect(hint).not.toBeNull();

    // Material's default reserves exactly one line under a field and positions the hint absolutely
    // inside it. That is right for the word "required" and wrong for every hint in this application,
    // which is a sentence explaining what the field is for — so each of them was drawn out of the
    // field's own box and over whatever sat beneath. MAT_FORM_FIELD_DEFAULT_OPTIONS in app.config.ts
    // sets subscriptSizing to 'dynamic', which takes the hint out of the absolute box and lets the
    // subscript grow with what it holds.
    //
    // The position is what is asserted, because it is the property that decides whether the hint can
    // overflow at all. A height would depend on the font the renderer picked and would pass or fail
    // for reasons having nothing to do with the setting.
    expect(getComputedStyle(hint as Element).position)
      .withContext(
        'the hint is positioned absolutely, so a hint longer than one line is drawn over whatever ' +
          'follows the field. See MAT_FORM_FIELD_DEFAULT_OPTIONS in app.config.ts.',
      )
      .not.toBe('absolute');
  });
});
