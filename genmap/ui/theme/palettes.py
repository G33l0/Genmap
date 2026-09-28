"""Colour palettes. Restrained, high contrast, and readable for long sessions."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Palette:
    name: str
    is_dark: bool
    window: str
    surface: str
    surface_alt: str
    border: str
    border_strong: str
    text: str
    text_muted: str
    accent: str
    accent_hover: str
    accent_pressed: str
    accent_text: str
    success: str
    warning: str
    danger: str
    info: str
    selection: str
    selection_text: str
    input_bg: str
    sidebar_bg: str
    sidebar_text: str
    sidebar_muted: str
    sidebar_selected_bg: str
    sidebar_selected_text: str
    sidebar_hover_bg: str
    console_bg: str
    console_text: str
    console_stderr: str
    badge_bg: str
    ui_font_family: str | None = None


LIGHT = Palette(
    name="light",
    is_dark=False,
    window="#F2F4F7",
    surface="#FFFFFF",
    surface_alt="#F7F8FA",
    border="#D6DAE1",
    border_strong="#B8BEC8",
    text="#1B1F27",
    text_muted="#5F6875",
    accent="#2457C5",
    accent_hover="#1F4DAF",
    accent_pressed="#1A4196",
    accent_text="#FFFFFF",
    success="#1E7B3E",
    warning="#A85F00",
    danger="#B32A2A",
    info="#2457C5",
    selection="#D7E3FB",
    selection_text="#1B1F27",
    input_bg="#FFFFFF",
    sidebar_bg="#1F2732",
    sidebar_text="#E7EBF0",
    sidebar_muted="#8E99A8",
    sidebar_selected_bg="#2F3B4B",
    sidebar_selected_text="#FFFFFF",
    sidebar_hover_bg="#28323F",
    console_bg="#171B22",
    console_text="#DDE2E9",
    console_stderr="#F2B8B8",
    badge_bg="#E9ECF1",
)

DARK = Palette(
    name="dark",
    is_dark=True,
    window="#1B1E24",
    surface="#23272F",
    surface_alt="#2A2F38",
    border="#363C47",
    border_strong="#4A5262",
    text="#E4E7EC",
    text_muted="#98A1AE",
    accent="#4A85E8",
    accent_hover="#5C93EC",
    accent_pressed="#3B74D3",
    accent_text="#FFFFFF",
    success="#3FBF6C",
    warning="#E3A13A",
    danger="#E4605F",
    info="#5C93EC",
    selection="#324A73",
    selection_text="#FFFFFF",
    input_bg="#1E2229",
    sidebar_bg="#15181D",
    sidebar_text="#DDE2E9",
    sidebar_muted="#7E8794",
    sidebar_selected_bg="#2A3140",
    sidebar_selected_text="#FFFFFF",
    sidebar_hover_bg="#20262F",
    console_bg="#111318",
    console_text="#D3D8DF",
    console_stderr="#F0A6A6",
    badge_bg="#2F3540",
)

HACKER = Palette(
    name="hacker",
    is_dark=True,
    window="#07090A",
    surface="#0C1110",
    surface_alt="#111A17",
    border="#1C3A2A",
    border_strong="#2A5A40",
    text="#B8F5C8",
    text_muted="#6FB48A",
    accent="#22D36B",
    accent_hover="#3BE884",
    accent_pressed="#19B85A",
    accent_text="#03140A",
    success="#3BE884",
    warning="#E6C84A",
    danger="#FF6B6B",
    info="#4FD1C5",
    selection="#133D27",
    selection_text="#D8FFE4",
    input_bg="#050807",
    sidebar_bg="#040605",
    sidebar_text="#9EEBB5",
    sidebar_muted="#4E8F68",
    sidebar_selected_bg="#0F2E1E",
    sidebar_selected_text="#3BE884",
    sidebar_hover_bg="#0A1D13",
    console_bg="#000000",
    console_text="#5CFF8F",
    console_stderr="#FF8080",
    badge_bg="#0F2E1E",
    ui_font_family="'Cascadia Mono', Consolas, 'JetBrains Mono', 'DejaVu Sans Mono', monospace",
)

PALETTES = {LIGHT.name: LIGHT, DARK.name: DARK, HACKER.name: HACKER}
THEME_CHOICES: tuple[tuple[str, str], ...] = (
    ("system", "Follow Windows setting"),
    ("light", "Light"),
    ("dark", "Dark"),
    ("hacker", "Hacker"),
)


def palette_by_name(name: str) -> Palette:
    return PALETTES.get(name, LIGHT)
